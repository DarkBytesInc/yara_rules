rule Win_Downloader_Dluca_6
{
strings:
	$a0 = { 7879608015ab80f6c980b5ca8016d68078d780d3e7804ef88083fb8035fcf9683cf409414f4c206ad21432350883c12ab2eaa030cf1130a7eb18c05bae700b4b048d24b5711e08a120344ca17225ac054d4449c6cf99a07b7345484847bc2a57c07cc1212573202dcb590a0703cb85954d1cc096 }

condition:
	$a0
}

        