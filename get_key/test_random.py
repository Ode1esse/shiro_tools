import random
import string
import base64

flags = []

for i in range(50):
    a = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))
    flags.append(a)

print(flags)

