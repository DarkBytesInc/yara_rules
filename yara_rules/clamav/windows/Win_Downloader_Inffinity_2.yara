rule Win_Downloader_Inffinity_2
{
strings:
	$a0 = { 66736F2E4F70656E5465787446696C652873332B225C5C6164645F6A732E6A73222C3129 }
	$a1 = { 76617220736F7572636532203D2066322E52656164416C6C2829 }
	$a2 = { 6576616C28736F7572636532293B }
	$a3 = { 69662028747970656F662076203D3D3D2022737472696E6722202626206B203D3D20226E616D65222026262076203D3D206E616D6529207B }
	$a4 = { 4A534F4E2E737472696E67696679286D795F6F626A2C2066756E6374696F6E20286B65792C2076616C756529207B }
	$a5 = { 7661722066203D2066736F2E4F70656E5465787446696C652866696C655F706174682C32293B }
	$a6 = { 662E5772697465286A736F6E5F656E636F646564293B }
	$a7 = { 666F722028766172206B657920696E206D795F6F626A2E726F6F74732E626F6F6B6D61726B5F6261722E6368696C6472656E29207B0D0A2F2F09575363726970742E6563686F286B657929 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7
}

        