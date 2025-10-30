# run in same env (save as test_vt.py)
from dotenv import load_dotenv
load_dotenv()
from app.connectors import vt_connector
print(vt_connector.vt_domain_report("alflying.bid"))
