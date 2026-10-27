echo "alias awgtop='source ~/awgtop/.venv/bin/activate; python ~/awgtop/awgtop.py'"
cd awgtop
python -m venv .venv
source .venv/bin/activate
pip install -r requiremenst.txt
exit
