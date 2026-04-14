"""
generate_data.py — Run once to create superstore_sales.csv
Mirrors the schema of the famous Kaggle 'Sample - Superstore' dataset.
"""
import csv, random
from datetime import datetime, timedelta

random.seed(42)

SEGMENTS   = ["Consumer", "Corporate", "Home Office"]
SHIP_MODES = ["Standard Class", "Second Class", "First Class", "Same Day"]
REGIONS    = ["West", "East", "Central", "South"]

CATEGORIES = {
    "Furniture":        ["Chairs", "Tables", "Bookcases", "Furnishings"],
    "Office Supplies":  ["Binders", "Paper", "Storage", "Appliances", "Labels", "Pens"],
    "Technology":       ["Phones", "Accessories", "Machines", "Copiers"],
}

PRODUCTS = {
    "Chairs":      ["Hon 5400 Series Task Chair","Chromcraft Bull-Nose Wood Table","Lesro Sheffield Series Lounge Chair"],
    "Tables":      ["Bretford CR4500 Series Slim Rectangular Table","Bevis Steel Folding Table","Iceberg Nesting Folding Table"],
    "Bookcases":   ["Sauder Classic Bookcase","Bush Westfield Collection Bookcase","O'Sullivan Plantations Bookcase"],
    "Furnishings": ["Eldon Expressions Desk Accessories","Howard Miller 13-3/4\" Diameter Goose Neck Clock"],
    "Binders":     ["Avery Durable Slant Binders","Cardinal Slant-D Ring Binder","Ibico Multi-Punch"],
    "Paper":       ["Hammermill Copy Plus Paper","Xerox 1967","Southworth 25% Cotton Rag Paper"],
    "Storage":     ["Eldon Fold 'N Roll Cart System","Fiskars 8\" Non-Stick Softgrip","Avery 200-Pack Clear Sheet Protectors"],
    "Appliances":  ["Belkin 8-Outlet Surge Suppressor","GBC DocuBind TL200 Binding","Fellowes PB500 Electric Punch"],
    "Labels":      ["Avery 494 Gold Seal Labels","Avery 496 Brown Kraft Labels"],
    "Pens":        ["SAFCO Velcro Fastener","Staple-based Ink Pen Set"],
    "Phones":      ["Samsung Galaxy S8","Nokia Smart Phone","Apple iPhone 12","Motorola Edge 5G"],
    "Accessories": ["Logitech MX Master Mouse","Anker USB-C Hub","Belkin USB Cable"],
    "Machines":    ["Lexmark MX611dhe Monochrome Laser Printer","HP LaserJet 600 M602 Printer"],
    "Copiers":     ["Canon imageCLASS MF8580Cdw","Hewlett Packard LaserJet 3310 Copier"],
}

CITIES_BY_REGION = {
    "West":    [("Los Angeles","California"),("Seattle","Washington"),("San Francisco","California"),("Phoenix","Arizona"),("Denver","Colorado")],
    "East":    [("New York City","New York"),("Philadelphia","Pennsylvania"),("Boston","Massachusetts"),("Jacksonville","Florida"),("Baltimore","Maryland")],
    "Central": [("Chicago","Illinois"),("Houston","Texas"),("Dallas","Texas"),("Detroit","Michigan"),("Columbus","Ohio")],
    "South":   [("Atlanta","Georgia"),("Nashville","Tennessee"),("Memphis","Tennessee"),("New Orleans","Louisiana"),("Charlotte","North Carolina")],
}

CUSTOMERS = [
    "Claire Gute","Darrin Van Huff","Sean O'Donnell","Brosina Hoffman",
    "Andrew Allen","Irene Maddox","Harold Pawlan","Pete Kriz",
    "Alejandro Grove","Zuschuss Donatelli","Ken Black","Sanjit Engle",
    "Elpida Pitt","Lela Donovan","Nora Preis","Seth Vernon",
    "Maria Bertelson","Tamara Chand","Raymond Buch","Hunter Lopez",
    "Andy Reiter","Kunst Miller","Odella Nelson","Wikus van de Merwe",
    "Priya Sharma","Aisha Patel","Mohammed Al-Hassan","Fatima Chen",
    "Ravi Kumar","Elena Petrov",
]

rows = []
start = datetime(2021, 1, 1)

for i in range(1, 301):
    region   = random.choice(REGIONS)
    city, state = random.choice(CITIES_BY_REGION[region])
    segment  = random.choice(SEGMENTS)
    customer = random.choice(CUSTOMERS)
    cat      = random.choice(list(CATEGORIES.keys()))
    sub_cat  = random.choice(CATEGORIES[cat])
    product  = random.choice(PRODUCTS.get(sub_cat, ["Generic Product"]))
    ship     = random.choice(SHIP_MODES)
    qty      = random.randint(1, 14)

    base_price = {
        "Technology": random.uniform(50, 1500),
        "Furniture":  random.uniform(80, 900),
        "Office Supplies": random.uniform(5, 120),
    }[cat]

    sales    = round(base_price * qty, 2)
    discount = random.choice([0.0, 0.0, 0.0, 0.1, 0.2, 0.3, 0.4, 0.5])
    profit   = round(sales * random.uniform(-0.15, 0.40), 2)
    odate    = (start + timedelta(days=random.randint(0, 1000))).strftime("%Y-%m-%d")

    rows.append({
        "row_id":       i,
        "order_id":     f"US-{odate[:4]}-{100000 + i}",
        "order_date":   odate,
        "ship_mode":    ship,
        "customer_name": customer,
        "segment":      segment,
        "city":         city,
        "state":        state,
        "country":      "United States",
        "region":       region,
        "category":     cat,
        "sub_category": sub_cat,
        "product_name": product,
        "sales":        sales,
        "quantity":     qty,
        "discount":     discount,
        "profit":       profit,
    })

with open("superstore_sales.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"✅  Generated {len(rows)} rows → superstore_sales.csv")
