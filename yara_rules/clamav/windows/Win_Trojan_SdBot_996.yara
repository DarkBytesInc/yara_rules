rule Win_Trojan_SdBot_996
{
strings:
	$a0 = { e313b46661bf68ebcbb2a54669b7f502c893b1479bc273d809efd8737b7b0b4ed809ef43f7c1aa7bc9f98716dc716a1e548ad080afdea3c4fa0a790f247ef934a81ab9ba56d0c4ccc726f6eda7b0a7965b92d39095a0b68bb2adb73611b97ae2 }

condition:
	$a0
}

        
