#!/usr/bin/env python2

# Copyright (c) 2017, ESET
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from Crypto.Cipher import CAST
import sys
import argparse


def main():

	parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-e", "--encrypt", help="encrypt carbon file", required=False)
	parser.add_argument("-d", "--decrypt", help="decrypt carbon file", required=False)

	try:
		args = parser.parse_args()
	except IOError as e:
		parser.error(e)
		return 0

	if len(sys.argv) != 3:
		parser.print_help()
		return 0
	
	key = "\x12\x34\x56\x78\x9A\xBC\xDE\xF0\xFE\xFC\xBA\x98\x76\x54\x32\x10"
	iv = "\x12\x34\x56\x78\x9A\xBC\xDE\xF0"

	cipher = CAST.new(key, CAST.MODE_OFB, iv)
	
	if args.encrypt:
		plaintext = open(args.encrypt, "rb").read()
		while len(plaintext) % 8 != 0:
			plaintext += "\x00"
		data = cipher.encrypt(plaintext)	
		open(args.encrypt + "_encrypted", "wb").write(data)
	else:
		ciphertext = open(args.decrypt, "rb").read()
		while len(ciphertext) % 8 != 0:
			ciphertext += "\x00"
		data = cipher.decrypt(ciphertext)
		open(args.decrypt + "_decrypted", "wb").write(data)

if __name__ == "__main__":
	main()
