rule Win_Trojan_Mycon_1
{
strings:
	$a0 = { 22406563686f206f6666222026204043524c462026202273687574646f776e202d72202d742033303030222029200a46494c45434c4f53452028202442415446494c452029200a46494c45534554415454524942202820245348202c20222b525348222029200a454e444946200a245448554d425f4452495645203d20445249564547455444524956452028202252454d4f5641424c45222029 }

condition:
	$a0
}

        