rule Win_Downloader_879_1
{
strings:
	$a0 = { c31edd2715c3c0660ff35ac3595cf0d849a05cc50f8dc706ce158362829a7fb71a89452185edbd8e1c303417eeb6f3cfd8a27a4fcf28cfa751fc62f790aab8bce71b1189d74a6cc7ea845a889614ce19650c84d5f7d554197b926e1f }

condition:
	$a0
}

        
