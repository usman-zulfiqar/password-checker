import requests
import hashlib
import sys


def request_api_data(query_char):
	#Password API URL
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)

	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the API and tey again')
	return res

def get_passwrd_leak_count(hashes, hash_to_check):
	hashes =  (line.split(':') for line in hashes.text.splitlines())

	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

	
def pwned_api_check(password):
	#Check password if it exists in API responce
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char , tail = sha1password[:5], sha1password[5:]
	responce = request_api_data(first5_char)
	print(first5_char, tail)

	return get_passwrd_leak_count(responce, tail)


def main(args):
	for password in args:
		count = pwned_api_check(password)

		if count:
			print(f'{password} was found {count} times ..')
		else:
			print(f'{password} was not found. Carry On')

	return 'Done'
if __name__== '__main__':
	sys.exit(main(sys.argv[1:]))