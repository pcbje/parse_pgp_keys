#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64
import hashlib
from datetime import datetime
import struct
import logging
import json


import hunch.helper as helper
import hunch.abstract_module as abstract_module

logger = logging.getLogger(__name__)


class PGPDataParser(object):

  def __init__(self, data):
    self.packet_length_data = data[0:2]
    self.packet_length = struct.unpack('>h', self.packet_length_data)[0] + 2
    self.data = data[2:self.packet_length]

  def _to_hex(self, data):
    return ''.join('{:02X}'.format(ord(c)) for c in data)

  def _to_date(self, data):
    return struct.unpack('>I', data)[0]

  def parse(self):
    raise NotImplementedError(u'Please implement this method')


class PGPUserIDParser(PGPDataParser):

  def __init__(self, data):
    super(PGPUserIDParser, self).__init__(data)
    self.packet_length = struct.unpack('B', data[0])[0] + 1
    self.data = data[1:self.packet_length]

  def parse(self):
    return {
        u'type': u'user_id',
        u'user_id': self.data
    }


class PGPSignatureParser(PGPDataParser):

  signature_types = {
      0x10: u'generic certification',
      0x13: u'positive certification',
      0x18: u'subkey binding',
  }

  def parse_version_3_signature(self):
    sig_type = ord(self.data[2])
    signed_by = self._to_hex(self.data[7:7 + 8])

    parsed = {
        u'type': 'signature',
        u'version': 3,
        u'signature_type': self.signature_types.get(sig_type, sig_type),
        u'signed': self._to_date(self.data[3:7]),
        u'signed_by': signed_by,
        u'signed_by_key_id': signed_by[-8::]
    }

    return parsed

  def parse_version_4_signature(self):
    sig_type = ord(self.data[1])

    parsed = {
        u'type': 'signature',
        u'version': 4,
        u'signature_type': self.signature_types.get(sig_type, sig_type)
    }

    hashed_offset = 6
    hashed_length, = struct.unpack(
        '>h', self.data[
            hashed_offset - 2:hashed_offset])

    unhashed_offset = hashed_length + hashed_offset
    unhashed_length, = struct.unpack(
        '>h', self.data[
            unhashed_offset:unhashed_offset + 2])

    subpackets = self.data[hashed_offset:unhashed_offset]
    subpackets += self.data[
        unhashed_offset + 2:unhashed_offset + 2 + unhashed_length]

    offset = 0

    while offset < len(subpackets):
      first_octet = ord(subpackets[offset])

      if first_octet == 255:
        length_length = 5
        length = struct.unpack('>I', subpackets[offset + 1:offset + 1 + 5])

      elif first_octet >= 192:
        length_length = 2
        length = ((first_octet - 192) << 8) + \
            (ord(subpackets[offset + 1])) + 192

      else:
        length_length = 1
        length = first_octet

      subpacket_type = ord(subpackets[offset + length_length])

      subpacket = subpackets[
          offset + length_length + 1:offset + length_length + length]

      if subpacket_type == 2:
        parsed[u'signed'] = self._to_date(subpacket)

      elif subpacket_type == 9:
        parsed[u'valid_for'] = self._to_date(subpacket)

      elif subpacket_type == 16:
        signed_by = "".join("{:02X}".format(ord(c)) for c in subpacket)
        parsed[u'signed_by'] = signed_by
        parsed[u'signed_by_key_id'] = signed_by[-8::]

      offset += length + length_length

    if u'signed' in parsed and u'valid_for' in parsed:
      parsed[u'expires'] = parsed[u'signed'] + parsed[u'valid_for']
      del parsed[u'valid_for']

    return parsed

  def parse(self):
    version = ord(self.data[0])

    if version == 3:
      return self.parse_version_3_signature()
    else:
      return self.parse_version_4_signature()


class PublicKeyParser(PGPDataParser):

  def _get_encryption_algorithm(self):
    algorithm_id, = struct.unpack('>b', self.data[5])

    if algorithm_id in set([1, 2, 3]):
      return u'rsa'

    elif algorithm_id in set([16, 20]):
      return u'elgamal'

    elif algorithm_id == 17:
      return u'dsa'

    else:
      raise ValueError(u'Unknown algorithm id %s' % algorithm_id)

  def _get_key_length(self):
    return struct.unpack('>h', self.data[6:8])[0]

  def _compute_fingerprint(self):
    digest = hashlib.sha1()
    digest.update(chr(0x99))
    digest.update(self.packet_length_data)
    digest.update(self.data)
    return digest.hexdigest().upper()

  def parse(self):
    version = ord(self.data[0])

    if version == 4:
      fingerprint = self._compute_fingerprint()
    else:
      raise ValueError(u'Unsupported key version %s' % version)

    return {
        u'type': u'public_key',
        u'version': version,
        u'fingerprint': fingerprint,
        u'key_id': fingerprint[-8::],
        u'created': self._to_date(self.data[1:5]),
        u'encryption_algorithm': self._get_encryption_algorithm(),
        u'key_length': self._get_key_length()
    }


class PublicSubKeyParser(PGPDataParser):

  def parse(self):
    return None


class Module(abstract_module.Module):
  PARSERS = {
      2: PGPSignatureParser,
      5: PublicKeyParser,
      6: PublicKeyParser,
      13: PGPUserIDParser,
      14: PublicSubKeyParser
  }

  def __init__(self, pipeline, worker_count):
    self.pipeline = pipeline
    self.pipeline.publishes([helper.META_TEXT])
    self.pipeline.subscribe(helper.EXTRACTED_TEXT, self.parse)

  def _process_packet(self, data, offset, packets):
    tag = (ord(data[offset]) & 0x3f) >> 2

    if tag not in self.PARSERS:
      raise ValueError(u'Unknown tag %s' % tag)

    parser = self.PARSERS[tag](data[offset + 1::])
    packet = parser.parse()

    if packet:
      packets.append(packet)

    return parser.packet_length + 1

  def _format_date(self, date):
    try:
      return datetime.utcfromtimestamp(date).strftime(
          u'%Y-%m-%dT%H:%M:%SZ').decode(u'utf-8')
    except TypeError:
      return date

  def _next_armored(self, text):
    lines = text.splitlines()

    start = False
    current = []

    for line in lines:
      line = line.strip()
      if line == u'-----BEGIN PGP PUBLIC KEY BLOCK-----':
        start = True
        current.append(line)
      elif line == u'-----END PGP PUBLIC KEY BLOCK-----':
        if start:
          current.append(line)
          yield '\n'.join(current)
          current = []
      elif start:
        current.append(line)

  def _get_decoded(self, armored):
    lines = armored.splitlines()
    start = 0
    for i in range(len(lines)):
      if lines[i] == u'':
        start = i + 1
        break
    encoded = u''.join(lines[start:-2])
    return base64.b64decode(encoded)

  def parse(self, data):
    if 'BEGIN PGP PUBLIC KEY BLOCK' not in data[helper.TEXT]:
      return

    pgp_keys = []

    for armored in self._next_armored(data[helper.TEXT]):
      decoded = self._get_decoded(armored)

      offset = 0
      packets = []

      while offset < len(decoded):
        try:
          offset += self._process_packet(decoded, offset, packets)
        except Exception as err:
          logger.debug(
              u'Unable to parse PGP key from "%s": %s' %
              (data[
                  helper.FILE_PATH],
                  err))
          break

      pgp_key = {}
      valid = False

      for packet in packets:
        if packet.get('type') == u'public_key':
          packet[u'created'] = self._format_date(packet.get(u'created'))
          valid = True

        elif packet.get('type') == 'signature':
          packet[u'signed'] = self._format_date(packet.get(u'signed'))
          packet[u'expires'] = self._format_date(
              packet.get(
                  u'expires',
                  u'never'))

        pgp_key.update(packet)

      if valid:
        del pgp_key[u'type']
        pgp_keys.append(pgp_key)

    if len(pgp_keys) > 0:
      self.pipeline.artifact(data, u'pgp_keys', pgp_keys)
      data[helper.TEXT] = json.dumps(pgp_keys)
      data[helper.PAGE_ID] = 0
      self.pipeline.publish(helper.META_TEXT, data)
