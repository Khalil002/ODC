
input = b"/bin/sh\x00"
inverted = input[::-1]
print(inverted)
print(inverted.hex())