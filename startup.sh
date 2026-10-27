#!/bin/bash
set -e

cd "$HOME/awgtop"

# Пересоздаём окружение, если Python отсутствует
if [ ! -x .venv/bin/python ]; then
    rm -rf .venv
    /usr/bin/python3 -m venv .venv
fi

# Устанавливаем зависимости
.venv/bin/python -m pip install -r requirements.txt

# Добавляем alias в bashrc
echo "alias awgtop='~/awgtop/.venv/bin/python ~/awgtop/awgtop.py; cd ~/'" >> ~/.bashrc

echo "Установка завершена!"

sleep 3
exit
