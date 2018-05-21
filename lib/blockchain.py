# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading

from . import util
from . import bitcoin
from . import constants
from .bitcoin import *
from decimal import Decimal
from decimal import getcontext



try:
    import scrypt
    getPoWHash = lambda x: scrypt.hash(x, x, N=1024, r=1, p=1, buflen=32)
except ImportError:
    util.print_msg("Warning: package scrypt not available; synchronization could be very slow")
    from .scrypt import scrypt_1024_1_1_80 as getPoWHash

MAX_TARGET = 0x00000FFFFF000000000000000000000000000000000000000000000000000000

def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

def deserialize_header(s, height):
    if not s:
        raise Exception('Invalid header: {}'.format(s))
    if len(s) != 80:
        raise Exception('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    h['block_height'] = height
    return h

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))

def pow_hash_header(header):
    return hash_encode(getPoWHash(bfh(serialize_header(header))))


blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)
    return blockchains

def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.checkpoints = constants.net.CHECKPOINTS
        self.parent_id = parent_id
        self.lock = threading.Lock()
        self.outliers = 0; # Keep track of failed header verifications
        with self.lock:
            self.update_size()

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//80 if os.path.exists(p) else 0

    def verify_header(self, header, prev_hash, bits, target, check_bits_target=True):
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return
        if check_bits_target:
            if bits != header.get('bits'):
                print("bits mistmatch at height %d" % header.get('block_height') + ", outliers++")
                #raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
                # increase count of failed verifications
                self.outliers += 1

            _powhash = pow_hash_header(header)
            if int('0x' + _powhash, 16) > target:
                raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _powhash, 16), target))

    def should_check_bits_target(self, height):
        if 'ANDROID_DATA' in os.environ:
            return False
        index = height // 2016
        return (index > len(self.checkpoints) + 1) or \
             (index < len(self.checkpoints) and height % 2016 == 0)

    def verify_chunk(self, index, data):
        num = len(data) // 80
        prev_hash = self.get_hash(index * 2016 - 1)
        headers = {}
        for i in range(num):
            raw_header = data[i*80:(i+1) * 80]
            header = deserialize_header(raw_header, index*2016 + i)
            headers[header.get('block_height')] = header

            bits, target = None, None
            check_bits_target = self.should_check_bits_target(index * 2016 + i)
            if(check_bits_target):
                bits, target = self.get_target((index * 2016 + i), headers)

            self.verify_header(header, prev_hash, bits, target, check_bits_target)
            prev_hash = hash_header(header)
            # If the number of failed verifications reaches higher than 10%, shit a brick
            if(self.outliers / 2016 > 0.1):
                raise BaseException("10 percent or more of the chunk is invalid")
        # reset verfication count for each chunk
        self.outliers = 0

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * 2016 - self.checkpoint) * 80
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        truncate = index >= len(self.checkpoints)
        self.write(chunk, d, truncate)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        with open(parent.path(), 'rb') as f:
            f.seek((checkpoint - parent.checkpoint)*80)
            parent_data = f.read(parent_branch_size*80)
        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*80)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*80:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.checkpoint
        data = bfh(serialize_header(header))
        assert delta == self.size()
        assert len(data) == 80
        self.write(data, delta*80)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        if os.path.exists(name):
            with open(name, 'rb') as f:
                f.seek(delta * 80)
                h = f.read(80)
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise Exception('Electrum datadir does not exist. Was it deleted while running?')
        else:
            raise Exception('Cannot find headers file but datadir is there. Should be at {}'.format(name))
        if h == bytes([0])*80:
            return None
        return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif height < len(self.checkpoints) * 2016:
            assert (height+1) % 2016 == 0, height
            index = height // 2016
            h, _, _ = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height))

    def get_timestamp(self, height):
        if height < len(self.checkpoints) * 2016 and (height+1) % 2016 == 0:
            index = height // 2016
            _, _, ts = self.checkpoints[index]
            return ts
        return self.read_header(height).get('timestamp')

    def get_target(self, height, chain={}):
        if constants.net.TESTNET:
            return 0, 0
        if height <= 28:
            return 0x1e0ffff0, 0x00000FFFF0000000000000000000000000000000000000000000000000000000
        index = height // 2016
        #print("index %d" % index + " height %d" % height)
        if index < len(self.checkpoints) and (height % 2016 == 0):
            #print("Bailing early index < len(self.checkpoints)")
            _, t, b, _ = self.checkpoints[index]
            return b, t
        if height < 4300128:
            # newyorkcoin: go back the full period unless it's the first retarget
            first = self.read_header((height - 2016 - 1 if height > 2016 else 0))
            last = self.read_header(height - 1)
            if last is None:
                last = chain.get(height - 1)
            assert last is not None
            # bits to target
            bits = last.get('bits')
            #print("last read height %d" % last.get('block_height'))
            bitsN = (bits >> 24) & 0xff
            if not (bitsN >= 0x03 and bitsN <= 0x1e):
                raise BaseException("First part of bits should be in [0x03, 0x1e]")
            bitsBase = bits & 0xffffff
            if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
                raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
            target = bitsBase << (8 * (bitsN-3))
            if height % 2016 != 0:
                return bits, target
            # new target
            nActualTimespan = last.get('timestamp') - first.get('timestamp')
            nTargetTimespan = 2 * 60 * 60
            nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
            nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
            new_target = min(MAX_TARGET, (target*nActualTimespan) // nTargetTimespan)
            # convert new target to bits
            c = ("%064x" % int(new_target))[2:]
            while c[:2] == '00' and len(c) > 6:
                c = c[2:]
            bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
            if bitsBase >= 0x800000:
                bitsN += 1
                bitsBase >>= 8
            new_bits = bitsN << 24 | bitsBase
            #print("returning new bits")
            return new_bits, bitsBase << (8 * (bitsN-3))
        else:
            #print("returning kgw")
            return self.KimotoGravityWell(height, chain)

    def convbits(self, new_target):
        c = ("%064x" % int(new_target))[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits

    def convbignum(self, bits):
        bitsN = (bits >> 24) & 0xff
        if not (bitsN >= 0x03 and bitsN <= 0x1e):
            raise BaseException("First part of bits should be in [0x03, 0x1e]")
        bitsBase = bits & 0xffffff
        if not (bitsBase >= 0x8000 and bitsBase <= 0x7fffff):
            raise BaseException("Second part of bits should be in [0x8000, 0x7fffff]")
        target = bitsBase << (8 * (bitsN-3))
        return target

    def can_connect(self, header, check_height=True):
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            #self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        bits, target = None, None
        check_bits_target = self.should_check_bits_target(height)
        if(check_bits_target):
            #print("checking bits")
            bits, target = self.get_target(height)
        try:
            self.verify_header(header, prev_hash, bits, target, check_bits_target)
        except BaseException as e:
            #print("header not verified %s" % e)
            return False
        return True

    def KimotoGravityWell(self, height, chain={}):
        BlocksTargetSpacing = 0.5 * 60  # 30 seconds
        TimeDaySeconds = 60 * 60 * 24
        PastSecondsMin = TimeDaySeconds * 0.01
        PastSecondsMax = TimeDaySeconds * 0.14
        PastBlocksMin = PastSecondsMin / BlocksTargetSpacing
        PastBlocksMax = PastSecondsMax / BlocksTargetSpacing
        PastBlocksMass = 0

        new_target = 0
        new_bits = 0
        BlockReadingIndex = height - 1
        BlockLastSolvedIndex = height - 1
        TargetBlocksSpacingSeconds = BlocksTargetSpacing
        PastRateAdjustmentRatio = float(1)
        bnProofOfWorkLimit = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF



        if (BlockLastSolvedIndex <= 0 or BlockLastSolvedIndex < PastSecondsMin):
            #print("maybe here")
            new_target = bnProofOfWorkLimit
            new_bits = self.convbits(new_target)
            return new_bits, new_target

        last = chain.get(BlockLastSolvedIndex)
        if last == None:
            last = self.read_header(BlockLastSolvedIndex)


        for i in range(1, int(PastBlocksMax)+1):

            PastBlocksMass = PastBlocksMass + 1

            reading = chain.get(BlockReadingIndex)
            if reading == None:
                reading = self.read_header(BlockReadingIndex)
                chain[BlockReadingIndex] = reading

            if (reading == None or last == None):
                raise BaseException("Could not find previous blocks when calculating difficulty reading: " + str(BlockReadingIndex) + ", last: " + str(BlockLastSolvedIndex) + ", height: " + str(height))

            if (i == 1):
                PastDifficultyAverage = self.convbignum(reading.get('bits'))
            else:
                pastBits = reading.get('bits')
                PastDifficultyAverage = float(((self.convbignum(pastBits))- PastDifficultyAveragePrev) / float(i)) + PastDifficultyAveragePrev

            PastDifficultyAveragePrev = PastDifficultyAverage
            #print("Height %d" % reading.get('block_height') + " timestamp %d" % reading.get('timestamp'))
            PastRateActualSeconds = last.get('timestamp') - reading.get('timestamp')
            PastRateTargetSeconds = TargetBlocksSpacingSeconds * PastBlocksMass
            PastRateAdjustmentRatio = float(1.0)
            if (PastRateActualSeconds < 0):

                PastRateActualSeconds = 0.0

            if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
                PastRateAdjustmentRatio = float(PastRateTargetSeconds) / float(PastRateActualSeconds)
                #print("PastRateAactualseconds %d" % PastRateActualSeconds)

            EventHorizonDeviation = 1 + ((0.7084) * pow((float(PastBlocksMass)/float(144)), float(-1.228)))
            EventHorizonDeviationFast = EventHorizonDeviation
            EventHorizonDeviationSlow = float(1) / float(EventHorizonDeviation)

            if (PastBlocksMass >= PastBlocksMin):

                if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) or (PastRateAdjustmentRatio >= EventHorizonDeviationFast)):
                    break


            if (BlockReadingIndex < 1):
                break
            BlockReadingIndex = BlockReadingIndex - 1

        #print("PastDifficultyAverage %d" % PastDifficultyAverage)
        bnNew = PastDifficultyAverage
        if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
            bnNew *= float(PastRateActualSeconds)
            bnNew /= float(PastRateTargetSeconds)
        else:
            print("PastDifficultyAverage Unaltered")
        if (bnNew > bnProofOfWorkLimit):
            print("bnNew greater than proof of work limit")
            bnNew = bnProofOfWorkLimit

        # new target
        new_target = bnNew

        new_bits = self.convbits(new_target)

        #print("bits %d" % new_bits , "(", hex(new_bits),")")
        #print("target %d" % new_target)
        #print("PastRateAdjustmentRatio=",PastRateAdjustmentRatio,"EventHorizonDeviationSlow",EventHorizonDeviationSlow,"PastSecondsMin=",PastSecondsMin,"PastSecondsMax=",PastSecondsMax,"PastBlocksMin=",PastBlocksMin,"PastBlocksMax=",PastBlocksMax)
        return new_bits, new_target

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx, data)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk %d failed'%idx, str(e))
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // 2016
        for index in range(n):
            h = self.get_hash((index+1) * 2016 -1)
            print("getting bits to append to checkpoints")
            bits, target = self.get_target(index * 2016)
            cp.append((h, target, bits, index))
        return cp
