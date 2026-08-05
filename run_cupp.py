import hashlib
from cupp import functions
from cupp.helper import CONFIG_DATA

def my_print_to_file(filename, unique_list_finished):
    with open(filename, "w") as fh:
        unique_list_finished.sort()
        fh.write("\n".join(unique_list_finished))
    print("saved", filename, len(unique_list_finished))

functions.print_to_file = my_print_to_file

profile = {
    "name":"alice","surname":"johnson","nick":"aj","birthdate":"15071990",
    "wife":"bob","wifen":"","wifeb":"",
    "kid":"charlie","kidn":"","kidb":"",
    "pet":"","company":"",
    "words":[],"specialchars":False,"randnum":False,"leetmode":False,
}

functions.gen_list_from_profile(profile)

target = "968c2349040273dd57dc4be7e238c5ac200ceac5"
with open("alice.txt","r") as f:
    for pw in f:
        pw=pw.strip()
        if hashlib.sha1(pw.encode()).hexdigest()==target:
            print("PASSWORD:",pw); break
    else:
        print("no match in wordlist")
