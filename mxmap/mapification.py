import json, pandas as pd

# this is the original map data i got from a website
with open('ro_admin_lau_polygon.geojson') as f:
    gj = json.load(f)

# the mail classification resulted from running get_info.py on the csv i got from wikidata
df = pd.read_csv('mail_classification.csv').drop_duplicates(subset='itemLabel')

# normalizes locality names
df['name_key'] = df['itemLabel'].str.strip().str.lower()

#transforms the data frame into a python dictionary
lookup = df.set_index('name_key')[['classification','provider','mx','country','spf_foreign_keywords']].to_dict('index')

# loop through every polygon in the geojson, basically every locality on the map
for feature in gj['features']:
    key = feature['properties']['name'].strip().lower()

    #if we find the locality in our csv ,update everything we need to for the map
    if key in lookup:
        row = lookup[key]
        feature['properties']['classification'] = row['classification']
        feature['properties']['provider'] = str(row['provider']) if row['provider'] else 'unknown'
        feature['properties']['mx'] = str(row['mx']) if row['mx'] else 'unknown'
        feature['properties']['mail_country'] = str(row['country']) if row['country'] else 'unknown'
        feature['properties']['spf_foreign'] = str(row['spf_foreign_keywords']) if row['spf_foreign_keywords'] else ''
    else:
        # if we didnt have in the csv, it means theres no data on it
        feature['properties']['classification'] = 'no_data'

# get our final geosjon
with open('ro_mail_map.geojson', 'w') as f:
    json.dump(gj, f)

