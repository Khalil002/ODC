
#input = b"/challen"
input = b"ge/flag\0"
inverted = input[::-1]
print(inverted)
print(inverted.hex())