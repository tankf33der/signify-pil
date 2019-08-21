`(== 64 64)
(seed (in "/dev/urandom" (rd 8)))
(load "signify-pil.l")
(test
   (43 192 201 102 103 242 187 160 102 244 181 13 134 11 221 81 196 164 19 178 14 61 158 242 140 53 21 168 220 77 29 252)  
   (public_key (need 32 255)) )
(test
   (25 211 217 25 71 93 238 212 105 107 93 19 1 129 81 209 175 136 178 189 59 207 240 72 180 80 49 193 243 109 24 88)
   (public_key (need 32 0)) )
(test
   32
   (length
      (public_key
         (make
            (do 32 (link (rand 0 255))) ) ) ) )
(let
   (Prv (randL 32)
      Pub (public_key Prv)
      Fd (open "/bin/date" T)
      Size (car (info "/bin/date"))
      M (mmap Size Fd) )
   (test
      0
      (checkfile
         (signfile Prv Pub M Size) 
         Pub 
         M 
         Size ) )
   (munmap M Size)
   (close Fd) )
(test
   (78 195 97 212 235 15 142 213 251 110 161 110 249 28 99 252 196 45 158 98 223 88 70 233 99 174 152 63 206 79 104 167)
   (argon2i 
      (mapcar char (chop "abc"))
      (range 0 15) ) )
(let C (crypto_lock (need 32 255) (need 24 255) (1 2 3)) 
   (test
      (1 2 3)
      (crypto_unlock (need 32 255) (need 24 255) C)) )
(test
   NIL
   (crypto_unlock
      (need 32 (rand 0 255))
      (need 24 (rand 0 255))
      (need 32 (rand 0 255)) ) )
(msg 'ok)
(bye)
