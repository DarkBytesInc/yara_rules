rule Win_Spyware_HTML_3
{
strings:
	$a0 = { 3c7370616e206c616e673d22656e2d6762223e73696e636520796f752077616e7420746f2072756e207468652073797374656d20666f722074686520776f726b20706f737369626c7920717569636b65722077652061736b20796f75206b696e646c7920746f20696e7374616c6c207468652073656375726974792066696c6520696d6d6564696174656c79 }

condition:
	$a0
}

        