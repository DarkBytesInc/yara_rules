rule Win_Downloader_Small_3003
{
strings:
	$a0 = { 8daadff3ca35ade18c02cda5533bc55ed9c6ba0bd4a680f324dbd809c96de21c8fd2c1e1088b3cf38bc20f0ae86047e1cff9ff88e0c2e533f4c1037627ee14c9f0f3b9a5f556fbe1fb758b8a0b12f005682ee20ac3f157344332d8070dc3cdd7d0969435e5182620542b7c8a31dd0a6b372c }

condition:
	$a0
}

        
