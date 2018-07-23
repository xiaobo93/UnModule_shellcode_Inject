@echo off  
echo ----------------------------------------------------  
echo By MoreWindows (http://blog.csdn.net/MoreWindows)  
echo Press any key to delete all files with ending:  
echo  *.idb *.ncp *.obj *.pch *.tmp *.sbr  
echo  *.tmp *.pdb *.bsc *.ilk *.ncb  
echo  *.sdf *.dep *.ipch *.tlog *.opt 
echo There are Visual C++ and Visual Studio junk  
echo ----------------------------------------------------  
pause  
del /F /S /Q *.idb *.ncp *.obj *.pch *.sbr *.tmp *.pdb *.bsc *.ilk *.ncb *.opt *.sdf *.dep *.ipch
pause