rule Win_Downloader_VB_421
{
strings:
	$a0 = { cf8bd313b8c4edb2d370e05603dc5c40d9636fb785253f5443d50be1c453f6d851a5bbdd6e3fce641bcc6613d6523766707b5b82c957d42fedc3796bd0576e3760bb7fc4712bbdc7c17a2fd350eadf7eeb7f4c03c96100eece23eccc5800e9cb5a7df776dbc3bb6bf8c03bf2cb4f4f4700e5ba73bbb94bb0 }

condition:
	$a0
}

        
