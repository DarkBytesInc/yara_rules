rule Win_Trojan_SdBot_3081
{
strings:
	$a0 = { 12dbceb35905d5b80b62bfe3c3b233ea0c06b71bec61fabdbd7d41c7674b8be512212d72e9c3281ff10ea4e9d633eab05552a09caaf3a4ee0846f720d3b850446d88ffe525180b6909b04e237f549b0ed79ac900cdec8315d67280eb76c6eec955cb3acff24a82af6ba1eb79c5eb31a0856a04ecae8ed0e1aa8a1f }

condition:
	$a0
}

        
