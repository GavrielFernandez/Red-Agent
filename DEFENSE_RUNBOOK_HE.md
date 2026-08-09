# Runbook להגנת פרויקט - RedAgent

תאריך הגנה: 12/08/2026
שעת התחלה: 09:00
חדר: C203

## מטרה
להציג מערכת עובדת מקצה לקצה: הרצה, סימולציה, ניתוח ממצאים, והסבר תיאורטי.

## צ׳קליסט ערב לפני
1. להריץ בדיקת מערכת:
   C:/Users/User/AppData/Local/Microsoft/WindowsApps/python3.12.exe test_system.py
2. להריץ בדיקות דשבורד:
   C:/Users/User/AppData/Local/Microsoft/WindowsApps/python3.12.exe -m pytest -q test_dashboard_regressions.py
3. לוודא ש-Docker עולה:
   docker ps
4. לוודא Ollama מותקן ומוכן:
   ollama list
5. להכין יעד דמו:
   http://localhost:8080

## צ׳קליסט 45 דקות לפני ההגנה
1. להפעיל Ollama:
   ollama serve
2. להפעיל שירות יעד לדמו (בטוח ולוקאלי):
   docker run --rm -p 8080:80 kennethreitz/httpbin
3. להפעיל דשבורד:
   C:/Users/User/AppData/Local/Microsoft/WindowsApps/python3.12.exe app.py
4. לפתוח דפדפן:
   http://localhost:5000
5. בדיקת API מהירה:
   לפתוח http://localhost:5000/api/status ולוודא status=ok

## תסריט דמו מומלץ (8-10 דקות)
1. פתיחה (דקה)
   - מה הבעיה: בדיקות אבטחה ידניות איטיות ומפוזרות.
   - מה הפתרון: סוכן אוטונומי שמבצע תהליך מסודר ומפיק דוח.
2. ארכיטקטורה (דקה)
   - Flask Dashboard לניהול והרצה.
   - Orchestrator לשלבי בדיקה.
   - Tool Factory להרצת כלים.
   - Reporting ליצירת דוח מסכם.
3. הרצה חיה (3-4 דקות)
   - New Assessment
   - Target: http://localhost:8080
   - Type: url
   - Start Assessment
   - להראות מעבר שלבים בזמן אמת.
4. ממצאים ודוח (2 דקות)
   - צפייה בממצאים, דירוג חומרה, וסיכום.
   - להראות דוח מוכן עם המלצות תיקון.
5. סיום (דקה)
   - מגבלות ידועות.
   - איך משפרים: דיוק, כיסוי, וסקייל.

## מסרים עיקריים לבוחן
1. המערכת מפחיתה זמן בין בדיקה לניתוח תוצאות.
2. המערכת שומרת עקביות בין הרצות ומפיקה תוצרים חוזרים.
3. הסביבה בדמו היא בטוחה ולוקאלית לצורך הדגמה מבוקרת.

## שאלות ותשובות קצרות
1. למה Agent ולא סקריפט ליניארי?
   כי Agent מאפשר קבלת החלטות לפי תוצאות ביניים והתאמות בזמן ריצה.
2. איך מצמצמים False Positives?
   שילוב מספר בדיקות, הצלבת ראיות, וולידציה לפני סימון כממצא חמור.
3. מה הגבולות האתיים?
   ריצה רק מול יעדים מורשים, בדמו רק שירות לוקאלי נשלט.
4. מה המגבלות?
   תלות בתלויות סביבתיות (Docker/Ollama), ואיכות תוצאות שתלויה באיכות הקלט.
5. מה שיפור עתידי חשוב?
   שכבת ולידציה חזקה יותר וסיווג ממצאים מבוסס ביטחון.

## תכנית למידה קצרה עד יום ההגנה
1. תיאוריה ליבה
   - CIA Triad, CVE/CVSS, OWASP Top 10.
2. תיאוריה מתקדמת
   - STRIDE, Attack Surface, Risk Prioritization.
3. תיאוריה מעבר לפרויקט
   - ניהול סיכונים ארגוני, false positive/negative tradeoff, threat modeling.
4. חזרה בעל פה
   - לענות על 20 שאלות בלי לקרוא חומר.

## תוכנית גיבוי אם רכיב לא עולה
1. אם Ollama לא עולה
   - להציג תוצרים מהרצה קודמת מתוך logs ולהסביר תהליך מלא.
2. אם Docker לא עולה
   - להשתמש ביעד URL חלופי מורשה או בתסריט Offline.
3. אם הדשבורד לא עולה
   - להריץ בדיקות API ולהראות דוחות JSON קיימים.

## קבצים שכדאי להכיר בעל פה
- app.py
- run.py
- tools/tool_factory.py
- core/orchestrator.py
- reporting/report_generator.py
- test_system.py
- test_dashboard_regressions.py
