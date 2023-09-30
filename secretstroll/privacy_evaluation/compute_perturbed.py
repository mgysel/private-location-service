import csv
import random
import pandas as pd
    
f = lambda x: float(x) + 0.002 * random.SystemRandom().uniform(-1, 1)   

# reading the CSV file 
data= pd.read_csv("queries.csv", delimiter = " ", converters = {'lat':f, 'lon':f})

header = ['ip_address', 'lat', 'lon', 'timestamp', 'poi_type_query']
data2 = pd.DataFrame(data, columns=header)

data2.to_csv('perturbed_queries.csv', sep = " ", index = False)