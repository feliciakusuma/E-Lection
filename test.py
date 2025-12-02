import os, ctypes
# point to the DLL if not on PATH
os.add_dll_directory(r"C:\Users\Felicia Kusuma\Downloads\Voting\E-Lection\new_env\Lib\site-packages")
ctypes.CDLL(r"C:\Users\Felicia Kusuma\Downloads\Voting\E-Lection\new_env\Lib\site-packages.dll")

from fips203 import ML_KEM_768
pk, sk = ML_KEM_768.keygen()
ct, ss1 = ML_KEM_768.encaps(pk)
ss2 = ML_KEM_768.decaps(ct, sk)
assert ss1 == ss2, "KEM round-trip failed"
print("fips203 ML_KEM_768 OK ✅")