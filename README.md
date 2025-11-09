Решения для лабораторной работы №1 по криптографическим протоколам

Запуск 4 задания в контейнере docker SageMath:
```bash
docker run -it -v ${PWD}:/home/sage/projects sagemath/sagemath:latest
```
Потом внутри контейнера
```bash
cd projects
```
И вызвать главный файл
```bash
load('task4/answer.py')
```

Автор: Воронов Игорь Сергеевич