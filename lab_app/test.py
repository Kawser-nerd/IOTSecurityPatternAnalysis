import arrow
test = '2012-06-05 16:20:03'
print(arrow.get(test[:len(test) - 3], 'YYYY-MM-DD HH:mm'))