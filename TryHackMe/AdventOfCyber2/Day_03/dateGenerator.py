start_year = 2019
end_year = 2020


with open("dates.txt", "w") as fout:
	for year in range(start_year, end_year+1):
		for month in range(1,13):
			for day in range(1,32): # We don't have to worry about some minor inefficiencies in dates
				fout.write(f'{year}{month:02}{day:02}\n')

