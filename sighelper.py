#!/usr/bin/env python

import IPython
import argparse
import os
import shutil
import zipfile
import tempfile
import subprocess

__author__ = "Vitor Afonso, vitormafonso __at__ gmail.com"

help_description = """

	Searches for common strings in the APKs contained in a dir and removes the strings contained in a whitelist file.
	Uses the tools 'dexstrings' and 'strings' to extract strings.

 """

"""
requirements:
dexstrings needs to be in the PATH
strings needs to be in the PATH
"""

def get_from_dexstrings(path):
	"""Get strings using the dexstrings tool.
	@param path: path to the file.
	@return: set with strings.
	"""
	try:
		strings = subprocess.check_output(['dexstrings', path], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError:
		# probably not a dex file, so just skip it
		return set()
	strings = strings.splitlines()[4:] # skil the inial lines with messages from the tool
	# output format is: ID | I1 | I2 | .:STRING:.
	string_set = set()
	for s in strings:
		s = s.replace('|'.join(s.split('|')[:3]), '', 1) # changes to: | .:STRING:.
		s = s[4:-2] # keeps only STRING
		string_set.add(s)
	return string_set

def get_from_strings_cmd(path, strings_len):
	"""Get strings using the 'strings' cmd.
	@param path: path to the file.
	@param strings_len: len argument used
	@return: set with strings.
	"""
	strings = subprocess.check_output(['strings', '-n', strings_len, path])
        strings = strings.splitlines()
        string_set = set()
        for s in strings:
                s = s.strip()
                string_set.add(s)
        return string_set

def get_strings_from_file(path, strings_len):
	"""Get the strings from the given file.
	@param path: path to file
	@param strings_len: min string size used with strings cmd
	@return: set with strings.
	""" 
	dexstrings = get_from_dexstrings(path)
	strings = get_from_strings_cmd(path, strings_len)
	return dexstrings | strings

def unzip_apk(path):
	"""Unzip file and returns dir with extracted files.
	@param path: zip file.
	@return: string with path of dest dir.
	"""
	dstdir = tempfile.mkdtemp() 
	zip_ref = zipfile.ZipFile(path, 'r')
	zip_ref.extractall(dstdir)
	zip_ref.close()
	return dstdir

def log(msg):
	"""Prints log messages if debug is enabled.
	@param msg: message.
	"""
	global DEBUG
	if DEBUG: print "[+] %s" % msg

def warn(msg):
	"""Prints the warning message:
	@param msg: message.
	"""
	print "[!] %s" % msg

def add_strings_to_map(map_strings, strings, file_path, apk):
	"""Add the mapping between file:apk and strings.
	@param map_strings: dict; [STRING] = set(APK1:FILEx, APK2:FILEy, ...) for each string, keep the set of apks and files that contain it
	@param strings: set with strings
	@param file_path: path of the file that contains these strings
	@param apk: apk name
	@param strings_len: string with min size of strings
	"""
	file_combo = file_path+":"+apk
	for string in strings:
		if not string in map_strings: map_strings[string] = set()
		map_strings[string].add(file_combo)

def filter_by_size(strings, strings_len):
	"""Removes the strings whose size is lower than strings_len.
	@param strings: set with strings
	@param strings_len: min size of strings
	"""
	to_remove = set()
	for string in strings:
                if len(string) < int(strings_len):
			to_remove.add(string)
	for s in to_remove: strings.remove(s)

def print_strings(common_strings, map_strings):
	"""Print each string and where it was found in each apk
	@param common_strings: set of strings
	@param map_strings: dict; [STRING] = set(APK1:FILEx, APK2:FILEy, ...) for each string, keep the set of apks and files that contain it
	"""
	for string in common_strings:
		print "Candidate: %s" % string
		for src in map_strings[string]:
			print "\tFound in %s" % src

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Find strings shared by some APKs that are not contained in a whitelist. The whitelist is generated from popular apps.')
	parser.add_argument('-d', '--dir', dest='dir', required=True, metavar='DIR', help='Dir with the APKs')
	parser.add_argument('--whitelist', dest='whitelist', required=False, default='whitelist_strings.txt', metavar='FILE', help='File with strings extracted from benign apps')
	parser.add_argument('--debug', dest='debug', required=False, default=False, action='store_true', help='Print debug messages.')
	parser.add_argument('-l', '--len', dest='strlen', required=False, default='5', metavar='SIZE', help='Min string size (default: 5).')
	parser.add_argument('--src', dest='printsrc', required=False, default=False, action='store_true', help='Print files where each string was found.')
	parser.add_argument('--onlydex', dest='onlydex', required=False, default=False, action='store_true', help='Only get strings from dex files (checks extension).')


	args = parser.parse_args()
	apksdir = args.dir
	DEBUG = args.debug
	strings_len = args.strlen
	printsrc = args.printsrc
	ONLY_DEX = args.onlydex

	map_strings = {} # [STRING] = [APK1:FILEx, APK2:FILEy, ...] for each string, keep the list of apks and files that contain it
	apks = os.listdir(apksdir)
	common_strings = set() # strings common to apks and not in the whitelist
	for apk in apks:
		log('Found apk %s' % apk)
		apk_path = os.path.join(apksdir, apk)
		log('Unzipping %s' % apk_path)
		unzipped_dir = unzip_apk(apk_path)
		log('Getting strings from %s' % unzipped_dir)
		str_curr_apk = set()
		for root, dirs, files in os.walk(unzipped_dir):
			for name in files:
				file_path = os.path.join(root, name)
				if ONLY_DEX and not (name.endswith('.smali') or name.endswith('.dex')): continue
				strings = get_strings_from_file(file_path, strings_len)
				filter_by_size(strings, strings_len)
				add_strings_to_map(map_strings, strings, file_path, apk)
				str_curr_apk |= strings
		# if its the first apk, common is empty
		if len(common_strings) == 0:
			common_strings = str_curr_apk 
		else:
			common_strings &= str_curr_apk
		log('Removing dir %s' % unzipped_dir)
		shutil.rmtree(unzipped_dir)

	if len(common_strings) == 0:
		warn('No common strings found')

	if printsrc:
		print_strings(common_strings, map_strings)
	else:
		for s in common_strings:
			print s

