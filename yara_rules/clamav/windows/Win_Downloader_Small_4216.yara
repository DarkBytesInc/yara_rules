rule Win_Downloader_Small_4216
{
strings:
	$a0 = { 9c7f96e82df42ea50c573df758bc14faef791e1c0224e5c77d3c0210123840f23ecfdf014054799fe7e70568684debf93570589e5f1b788003e1fcc5f3881c13bc15c74d0be7102c14dc87c31d8e10117c13d21660108ec3e10e34142818181158cf3bcff37c3c14861cbe6018f8106c14c3e170387a148c149c14a414ba14381c0e87c614dc14ea14f81404 }

condition:
	$a0
}

        