(unless (== 64 64)
   (msg "pil64 required")
   (bye 1) )
(seed (in "/dev/urandom" (rd 8)))
(setq *Dir (pack (pil) "signify-pil/"))
(or (info *Dir) (call "mkdir" "-p" *Dir))

(de gen NIL
   (unless (=1 (length (argv))) (quit "Wrong usage"))
   (let 
      (Proj (opt)
         PubF (pack *Dir Proj ".pub")
         PrvF (pack *Dir Proj ".prv")
         Prv (randL 32)
         Pub (public_key Prv)
         Salt (randL 16)
         Nonce (randL 24) )
      (when (or (info PubF) (info PrvF)) (quit "Fail, file(s) exists"))
      (prinl "Enter password for private key, press Enter:")
      (setq Prv 
         (crypto_lock
            (argon2i (mapcar char (in NIL (line))) Salt)
            Nonce
            Prv ) )
      (rc PubF 'Pub Pub)
      (rc PrvF 'Prv Prv)
      (rc PrvF 'Salt Salt)
      (rc PrvF 'Nonce Nonce)
      (bye) ) )
(de sign NIL
   (unless (= 2 (length (argv))) (quit "Wrong usage"))
   (let
      (Proj (opt)
         SignFile (opt)
         SignSize NIL
         SignFd NIL
         PubF (pack *Dir Proj ".pub")
         PrvF (pack *Dir Proj ".prv")
         Pass NIL
         M )
      (unless (and (info PubF) (info PrvF) (info SignFile))
         (quit "Fail, required files dont exist") )
      (prinl "Enter password for private key, press Enter")
      (setq 
         Pass (mapcar char (in NIL (line)))
         SignSize (car (info SignFile))
         SignFd (open SignFile T)
         M (mmap SignSize SignFd) )
      (if
         (crypto_unlock
            (argon2i Pass (rc PrvF 'Salt))
            (rc PrvF 'Nonce)
            (rc PrvF 'Prv) )
         (prinl
            (lowc
               (pack
                  (mapcar
                     '((B) (pad 2 (hex B)))
                      (signfile @ (rc PubF 'Pub) M SignSize) ) ) ) )
         (quit "Fail, wrong password") )
      (munmap M SignSize)
      (close SignFd)
      (bye) ) )
(de check NIL
   (unless (= 3 (length (argv))) (quit "Wrong usage"))
   (let
      (Proj (opt)
         CheckFile (opt)
         Signature (opt)
         CheckSize NIL
         CheckFd NIL
         PubF (pack *Dir Proj ".pub")
         M )
      (unless (and (info PubF) (info CheckFile))
         (quit "Fail, required files dont exist") )
      (unless (= 128 (length Signature))
         (quit "Fail, wrong input checksum") )
      (setq
         Signature (hex2L Signature)
         CheckSize (car (info CheckFile))
         CheckFd (open CheckFile T)
         M (mmap CheckSize CheckFd) )
      (if (n0 (checkfile Signature (rc PubF 'Pub) M CheckSize))
         (quit "Fail, check failed")
         (munmap M CheckSize)
         (close CheckFd)
         (msg 'ok)
         (bye) ) ) )
(de showpub NIL
   (unless (=1 (length (argv))) (quit "Wrong usage"))
   (let (Proj (opt)  PubF (pack *Dir Proj ".pub"))
      (unless (info PubF) (quit "Fail, file doesnt exist"))
      (prinl
         (lowc
            (pack
               (mapcar
                  '((B) (pad 2 (hex B)))
                  (rc PubF 'Pub) ) ) ) )
      (bye) ) )
(de addpub NIL
   (unless (= 2 (length (argv))) (quit "Wrong usage"))
   (let 
      (Proj (opt)
         Pub (hex2L (opt))
         PubF (pack *Dir Proj ".pub") )
      (when (info PubF) (quit "Fail, file exists"))
      (rc PubF 'Pub Pub)
      (bye) ) )
(de randL (N)
   (make (do N (link (rand 0 255)))) )
(de hex2L (H)
   (make
      (for (L (chop H) L (cddr L))
         (link (hex (pack (car L) (cadr L)))) ) ) )
(de mmap (L F)
   (native "@" "mmap" 'N 0 L 1 2 F 0) )
(de munmap (A L)
   (native "@" "munmap" 'N A L) )
(de public_key (S)
   (use P
      (native
         "libmonocypher.so.2"
         "crypto_sign_public_key"
         NIL
         '(P (32 B . 32))
         (cons NIL (32) S) )
      P ) )
# XXX: mmap
(de signfile (S P M ML)
   (use Sign
      (native
         "libmonocypher.so.2"
         "crypto_sign"
         NIL
         '(Sign (64 B . 64))
         (cons NIL (32) S)
         (cons NIL (32) P)
         M
         ML )
      Sign ) )
(de checkfile (S P M ML)
   (native
      "libmonocypher.so.2"
      "crypto_check"
      'I
      (cons NIL (64) S)
      (cons NIL (32) P)
      M
      ML ) )
(de argon2i (P S)
   (let (PL (length P)  H)
      (native
         "libmonocypher.so.2"
         "crypto_argon2i"
         NIL
         '(H (32 B . 32))
         32
         (list NIL (cons 104857600))
         102400
         4
         (cons NIL (cons PL) P)
         PL
         (cons NIL (16) S)
         16 )
      H ) )
(de crypto_lock (K N P)
   (let (PL (length P)  C NIL  M)
      (native
         "libmonocypher.so.2"
         "crypto_lock"
         NIL
         '(M (16 B . 16))
         (list 'C (cons PL 'B PL))
         (cons NIL (32) K)
         (cons NIL (24) N)
         (cons NIL (cons PL) P)
         PL )
      (conc C M) ) )
(de crypto_unlock (K N C)
   (let (CL (- (length C) 16)  P)
      (and
         (=0
            (native
               "libmonocypher.so.2"
               "crypto_unlock"
               'N
               (list 'P (cons CL 'B CL))
               (cons NIL (32) K)
               (cons NIL (24) N)
               (cons NIL (16) (tail 16 C))
               (cons NIL (cons CL) (head CL C))
               CL ) )
         P ) ) )
