echo "alias awgtop='~/awgtop/.venv/bin/python ~/awgtop/awgtop.py; cd ~/'"
cd ~/awgtop
python -m venv .venv
source .venv/bin/activate
pip install -r requiremenst.txt
exit
