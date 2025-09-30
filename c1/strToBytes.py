
input = b"/bin/sh\0"
inverted = input[::-1]
print(inverted)
print(inverted.hex())