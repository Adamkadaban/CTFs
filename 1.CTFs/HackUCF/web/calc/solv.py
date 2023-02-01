from requests import get, post


url = 'http://ctf.hackucf.org:4000/calc/calc.php'
r = get(url)

text = r.text
text = "".join(text[text.find("<expression>") + 12:text.find("</expression>")].split("<br/>"))

result = eval(text)

# print(expr)
# print(int(result))

payload = {"answer": str(int(result))}
p = post(url, data=payload, cookies=r.cookies.get_dict())
print(p.text)


