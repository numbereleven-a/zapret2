# AGENTS.md — правила статического аудита

## Цель
Провести полный статический анализ ТОЛЬКО nfq2/ и lua/ (внутри zapret2-master) по инструкции docs/manual.en.md.

## Обязательное состояние прогресса (источник правды)
- Веди файл audit/coverage.csv со столбцами: path,status,reason
- Статусы: pending | analyzed_full | analyzed_partial | skipped
- Работа считается завершённой ТОЛЬКО когда в audit/coverage.csv нет строк со статусом pending.

## Процедура
1) Построй полный SCOPE_LIST и запиши в audit/SCOPE_LIST.txt (отсортированный).
2) Синхронизируй audit/coverage.csv: каждая строка SCOPE_LIST должна присутствовать и иметь ровно один статус.
3) Иди по pending по одному файлу: открой, прочитай, проанализируй, запиши находки в audit/findings/<path>.md
4) Обнови строку в coverage.csv.
5) Повтори, пока pending=0.
6) В конце собери audit/report.md (triage + полный список проблем + bulk-fix + coverage summary).

## Scope и исключения
- Анализировать только файлы внутри nfq2/ и lua/
- Полностью исключить: *.sh, nfq2/gzip.c, nfq2/gzip.h, nfq2/Makefile, nfq2/BSDmakefile
- Не анализировать темы: build/setup, signal handlers (signal/sigaction/SIG*)
- Не тратить время на “известные пункты” из промпта пользователя (пропускать без упоминания)
