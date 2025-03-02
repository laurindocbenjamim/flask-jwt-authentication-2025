import requests
from bs4 import BeautifulSoup
import pandas as pd

db = "countries.db"
table = "countries"

csv_file = "countries.csv"
phonenumberULR = (
    "https://worldpopulationreview.com/country-rankings/phone-number-length-by-country"
)
with_length = "https://www.iban.com/dialing-codes"
url = "https://countrycode.org/"


def extract_countries(url):
    count = 0
    data_dict = {}
    tables_list = []
    if url is None:
        return None

    df = pd.DataFrame()
    columns = []
    rows = []

    tables = extract_tables(url)

    if len(tables) > 0:
        for table in tables:
            thead, tbody, rows, columns = extract_table_data(table, df)
            tables_list.append([thead, tbody, rows, columns])
            break
        

    if rows is not None and len(rows) > 0:
        for row in rows:
            if count < len(rows):
                col = row.find_all("td")

                if len(col) != 0:

                    try:
                        myList = []
                        for a in range(len(col)):
                            
                            if len(col) == len(columns):
                                item = get_each_tbody_item(col, a)
                                myList.append('null' if item is None or item == '' else item)
                                data_dict[columns[a]] = 'N/A' if item is None else item
                                
                            else:
                                data_dict[columns[a]] = "null"
                        df = pd.concat(
                                [
                                    df,
                                    pd.DataFrame(
                                        [
                                            myList
                                        ],
                                        columns=columns,
                                    ),
                                ],
                                ignore_index=True,
                            )                           
                       
                    except IndexError as e:
                        print(f"IndexError: {e}")
                    except Exception as e:
                        print(f"Error {e}")
                    count += 1
                
            else:
                break

        return df
        
    
    print(data_dict)
    return None


"""
Fisrt function to extract the tables
from the url
"""
def extract_tables(url):
  
    if url is None:
        return None

    html_page = requests.get(url).text
    data_soup = BeautifulSoup(html_page, "html.parser")
    table = data_soup.find_all("table")

    if len(table) > 0:
        return table
    
    return []


"""
Second function to extract the data from the tables like
thead, tbody, rows and columns
"""
def extract_table_data(table, df):
    count = 0
    columns = []
    if table is None:
        return None
    
    thead = table.find_all("thead")    
    tbody = table.find_all("tbody")
    rows = tbody[0].find_all("tr")
    # Extract the columns
    columns = get_each_head_item(thead)

    return thead, tbody, rows, columns


"""
This function will extract the columns items from the thead
"""
def get_each_head_item(thead):
    columns = []
    try:
        if thead is not None and len(thead) > 0:
            for th in thead[0].find_all("th"):
                columns.append(
                    th.contents[0]
                    .replace("\n", "")
                    .replace("\r", "")
                    .replace(" ", "")
                    .replace("\t", "")
                )
        return columns    
    except IndexError as e:
        return None
    except Exception as e:
        return None
    return None


"""
This function will extract the column items from the tbody rows

"""
def get_each_tbody_item(list, index):
    try:
        return list[index].contents[0].text
    except IndexError as e:
        return None
    except Exception as e:
        return None


"""
print("\n")
print("==================== EXTRACTED DATA FROM THE URL: {}\n".format(url))
print("\n")
df = extract_countries(url)
keys = df.keys()
data = []
for i, row in df.iterrows():
    data.append(dict(row))
print(data)
"""
