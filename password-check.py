import requests
import hashlib
import sys

def req_api_data(query_char):
    # Req api data and check response code
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and   try again')

    return res

def get_pw_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
 
def check_pwned_api(password):
    hashed_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5 = hashed_pw[:5]
    tail = hashed_pw[5:]
    response = req_api_data(first5)

    return get_pw_leaks_count(response, tail)

def main(args):
    for password in args:
        count = check_pwned_api(password)
        if count:
            print(f'{password} was found {count} times')
        else:
            print(f'{password} was not found')

        return 'done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))