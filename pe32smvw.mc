MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning=0x2:STATUS_SEVERITY_WARNING
    Error=0x3:STATUS_SEVERITY_ERROR
    )


FacilityNames=(System=0x0:FACILITY_SYSTEM
    Runtime=0x2:FACILITY_RUNTIME
    Stubs=0x3:FACILITY_STUBS
    Io=0x4:FACILITY_IO_ERROR_CODE
)

LanguageNames=(English=0x409:MSG00409)
LanguageNames=(Ukrainian=0x422:MSG00422)
LanguageNames=(Russian=0x419:MSG00419)

; // The following are message definitions.

MessageId=0x1
Severity=Success
Facility=Runtime
SymbolicName=MSG_PROCESSING_SUCCESS
Language=English
File %1 is processed successfully.
.
Language=Ukrainian
Вдала обробка файлу %1.
.
Language=Russian
Удачная обработка файла %1.
.
MessageId=0x1
Severity=Error
Facility=Runtime
SymbolicName=MSG_PROCESSING_FAILED
Language=English
File %1 processing is failed.
.
Language=Ukrainian
Невдала обробка файлу %1.
.
Language=Russian
Неудачная обработка файла %1.
.
MessageId=0x2
Severity=Error
Facility=Runtime
SymbolicName=MSG_UNHANDLED_EXCEPTION
Language=English
Unhandled exception is raised: %1.
.
Language=Ukrainian
Невідома помилка: %1.
.
Language=Russian
Неизвестная ошибка: %1.
.
