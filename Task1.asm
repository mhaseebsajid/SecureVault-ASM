; ============================================================
; SecureVault - Password Manager (FINAL FIXED VERSION)
; ============================================================
INCLUDE Irvine32.inc

MAX_ENTRIES  EQU 20
FIELD_LEN    EQU 32
XOR_KEY      EQU 0ABh
CAESAR_SHIFT EQU 3
MAX_ATTEMPTS EQU 3

.data
banner BYTE "================================================",0Dh,0Ah
       BYTE " SecureVault - Password Manager ",0Dh,0Ah
       BYTE " NASTP Institute - COAL Project ",0Dh,0Ah
       BYTE "================================================",0Dh,0Ah,0

menuStr BYTE 0Dh,0Ah
        BYTE " 1. Add New Password",0Dh,0Ah
        BYTE " 2. View All Passwords",0Dh,0Ah
        BYTE " 3. Search Password by Website",0Dh,0Ah
        BYTE " 4. Encrypt / Decrypt Text",0Dh,0Ah
        BYTE " 5. Generate Strong Password",0Dh,0Ah
        BYTE " 6. Exit",0Dh,0Ah,0Dh,0Ah
        BYTE " Enter choice: ",0

pinPrompt     BYTE " Enter Master PIN: ",0
pinWrong      BYTE " [!] Wrong PIN! Attempts left: ",0
pinLocked     BYTE " [X] Too many wrong attempts. Vault LOCKED.",0Dh,0Ah,0
pinOk         BYTE " [+] Access Granted! Welcome to SecureVault.",0Dh,0Ah,0

websitePrompt BYTE " Website : ",0
userPrompt    BYTE " Username : ",0
passPrompt    BYTE " Password : ",0

addedOk       BYTE " [+] Password saved successfully!",0Dh,0Ah,0
vaultFull     BYTE " [!] Vault is full!",0Dh,0Ah,0
noEntries     BYTE " [!] No passwords stored yet.",0Dh,0Ah,0
notFoundStr   BYTE " [!] Website not found.",0Dh,0Ah,0
searchPrompt  BYTE " Enter website to search: ",0

encPrompt BYTE " Enter text to encrypt: ",0
decPrompt BYTE " Enter text to decrypt: ",0
encChoice BYTE " 1-Encrypt 2-Decrypt : ",0
encResult BYTE " Encrypted : ",0
decResult BYTE " Decrypted : ",0

genLenPrompt BYTE " Enter desired length (8-20): ",0
genPrompt    BYTE " Generating strong password...",0Dh,0Ah,0
genResult    BYTE " Generated : ",0

divider   BYTE " ------------------------------------------------",0Dh,0Ah,0
pressKey  BYTE 0Dh,0Ah," Press any key to continue...",0Dh,0Ah,0
invalidChoice BYTE " [!] Invalid choice.",0Dh,0Ah,0

; Storage
masterPin BYTE "1234",0
websites  BYTE MAX_ENTRIES * FIELD_LEN DUP(0)
usernames BYTE MAX_ENTRIES * FIELD_LEN DUP(0)
passwords BYTE MAX_ENTRIES * FIELD_LEN DUP(0)
checksums DWORD MAX_ENTRIES DUP(0)
entryCount DWORD 0

; Buffers
pinBuffer BYTE FIELD_LEN DUP(0)
searchBuf BYTE FIELD_LEN DUP(0)
encBuf    BYTE FIELD_LEN*2 DUP(0)
genBuf    BYTE 32 DUP(0)
tempPass  BYTE FIELD_LEN DUP(0)
attemptsLeft DWORD MAX_ATTEMPTS
genLength DWORD 12

lowerChars   BYTE "abcdefghijklmnopqrstuvwxyz",0
upperChars   BYTE "ABCDEFGHIJKLMNOPQRSTUVWXYZ",0
digitChars   BYTE "0123456789",0
specialChars BYTE "!@#$%&*?",0

.code

StrCompare PROC
    push esi
    push edi
    mov esi, edx
    mov edi, eax
compareLoop:
    mov al, [esi]
    cmp al, [edi]
    jne notEqual
    cmp al, 0
    je equal
    inc esi
    inc edi
    jmp compareLoop
equal:
    xor eax, eax
    jmp done
notEqual:
    or eax, 1
done:
    pop edi
    pop esi
    ret
StrCompare ENDP

main PROC
    call Clrscr
    mov edx, OFFSET banner
    call WriteString
    call PinLock
    call Clrscr

mainLoop:
    mov edx, OFFSET banner
    call WriteString
    mov edx, OFFSET menuStr
    call WriteString
    call ReadChar
    call Crlf

    cmp al, '1'
    je doAdd
    cmp al, '2'
    je doView
    cmp al, '3'
    je doSearch
    cmp al, '4'
    je doEncrypt
    cmp al, '5'
    je doGenerate
    cmp al, '6'
    je doExit

    mov edx, OFFSET invalidChoice
    call WriteString
    jmp mainLoop

doAdd:
    call AddPassword
    jmp mainLoop
doView:
    call ViewPasswords
    jmp mainLoop
doSearch:
    call SearchPassword
    jmp mainLoop
doEncrypt:
    call EncryptMenu
    jmp mainLoop
doGenerate:
    call GeneratePassword
    jmp mainLoop
doExit:
    exit
main ENDP

; =============================================================
PinLock PROC
    pusha
pinTry:
    mov edx, OFFSET pinPrompt
    call WriteString
    mov edi, OFFSET pinBuffer
    mov ecx, 0
pinReadLoop:
    call ReadChar
    cmp al, 0Dh
    je pinDone
    cmp al, 08h
    je pinBack
    cmp ecx, FIELD_LEN-2
    jge pinReadLoop
    mov [edi+ecx], al
    inc ecx
    mov al, '*'
    call WriteChar
    jmp pinReadLoop
pinBack:
    cmp ecx, 0
    je pinReadLoop
    dec ecx
    mov al, 08h
    call WriteChar
    mov al, ' '
    call WriteChar
    mov al, 08h
    call WriteChar
    jmp pinReadLoop
pinDone:
    mov BYTE PTR [edi+ecx], 0
    call Crlf
    mov edx, OFFSET pinBuffer
    mov eax, OFFSET masterPin
    call StrCompare
    jz pinSuccess
    dec attemptsLeft
    mov edx, OFFSET pinWrong
    call WriteString
    mov eax, attemptsLeft
    call WriteDec
    call Crlf
    cmp attemptsLeft, 0
    je pinFail
    jmp pinTry
pinSuccess:
    mov edx, OFFSET pinOk
    call WriteString
    popa
    ret
pinFail:
    mov edx, OFFSET pinLocked
    call WriteString
    exit
PinLock ENDP

; =============================================================
AddPassword PROC
    pusha
    cmp entryCount, MAX_ENTRIES
    jl apContinue
    mov edx, OFFSET vaultFull
    call WriteString
    jmp apDone
apContinue:
    mov eax, entryCount
    imul eax, FIELD_LEN
    mov esi, eax

    mov edx, OFFSET websitePrompt
    call WriteString
    lea edx, websites[esi]
    mov ecx, FIELD_LEN-1
    call ReadString

    mov edx, OFFSET userPrompt
    call WriteString
    lea edx, usernames[esi]
    mov ecx, FIELD_LEN-1
    call ReadString

    mov edx, OFFSET passPrompt
    call WriteString
    lea edi, passwords[esi]
    call ReadMasked

    lea esi, passwords[esi]
    call XorCrypt
    mov bl, CAESAR_SHIFT
    call CaesarEncrypt

    call ComputeChecksum
    mov ebx, entryCount
    mov checksums[ebx*4], eax

    inc entryCount
    mov edx, OFFSET addedOk
    call WriteString

apDone:
    mov edx, OFFSET pressKey
    call WriteString
    call ReadChar
    popa
    ret
AddPassword ENDP

ReadMasked PROC
    pushad
    mov ecx, 0
rmLoop:
    call ReadChar
    cmp al, 0Dh
    je rmDone
    cmp al, 08h
    je rmBack
    cmp al, 20h
    jl rmLoop
    cmp ecx, FIELD_LEN-1
    jge rmLoop
    mov [edi+ecx], al
    inc ecx
    mov al, '*'
    call WriteChar
    jmp rmLoop
rmBack:
    cmp ecx, 0
    je rmLoop
    dec ecx
    mov al, 08h
    call WriteChar
    mov al, ' '
    call WriteChar
    mov al, 08h
    call WriteChar
    jmp rmLoop
rmDone:
    mov BYTE PTR [edi+ecx], 0
    call Crlf
    popad
    ret
ReadMasked ENDP

ComputeChecksum PROC
    push ebx
    push ecx
    push esi
    xor eax, eax
    xor ecx, ecx
csLoop:
    movzx ebx, BYTE PTR [esi+ecx]
    cmp bl, 0
    je csDone
    add eax, ebx
    inc ecx
    cmp ecx, FIELD_LEN
    jl csLoop
csDone:
    pop esi
    pop ecx
    pop ebx
    ret
ComputeChecksum ENDP

; ====================== FIXED VIEW ALL ======================
; =============================================================
; =============================================================
; =============================================================
; FIXED ViewPasswords PROC
; =============================================================
ViewPasswords PROC
    pusha

    ; No entries
    cmp entryCount, 0
    jne vpStart

    mov edx, OFFSET noEntries
    call WriteString
    jmp vpDone

vpStart:
    mov ecx, 0                  ; ECX = entry index

vpLoop:

    ; Check loop end
    cmp ecx, entryCount
    jge vpDone

    ; ==========================================
    ; offset = index * FIELD_LEN
    ; ==========================================
    mov eax, ecx
    imul eax, FIELD_LEN

    ; Save offset
    mov esi, eax

    ; ==========================================
    ; Divider
    ; ==========================================
    mov edx, OFFSET divider
    call WriteString

    ; ==========================================
    ; Website
    ; ==========================================
    mov edx, OFFSET websitePrompt
    call WriteString

    lea edx, websites[esi]
    call WriteString
    call Crlf

    ; ==========================================
    ; Username
    ; ==========================================
    mov edx, OFFSET userPrompt
    call WriteString

    lea edx, usernames[esi]
    call WriteString
    call Crlf

    ; ==========================================
    ; Copy encrypted password
    ; ==========================================
    lea esi, passwords[esi]
    lea edi, tempPass

    mov edx, ecx                ; SAVE LOOP COUNTER

    mov ecx, FIELD_LEN
    cld
    rep movsb

    mov ecx, edx                ; RESTORE LOOP COUNTER

    ; Null terminate
    mov BYTE PTR tempPass[FIELD_LEN-1], 0

    ; ==========================================
    ; Decrypt tempPass
    ; ==========================================
    lea esi, tempPass

    push ecx                    ; protect counter
    mov bl, CAESAR_SHIFT
    call CaesarDecrypt
    pop ecx

    lea esi, tempPass
    call XorCrypt

    ; ==========================================
    ; Print password
    ; ==========================================
    mov edx, OFFSET passPrompt
    call WriteString

    mov edx, OFFSET tempPass
    call WriteString
    call Crlf
    call Crlf

    ; Next entry
    inc ecx
    jmp vpLoop

vpDone:

    mov edx, OFFSET divider
    call WriteString

    mov edx, OFFSET pressKey
    call WriteString

    call ReadChar

    popa
    ret

ViewPasswords ENDP

; Rest of your procedures (Search, EncryptMenu, etc.) - kept as original
SearchPassword PROC
    pusha
    mov edx, OFFSET searchPrompt
    call WriteString
    mov edx, OFFSET searchBuf
    mov ecx, FIELD_LEN-1
    call ReadString
    mov ecx, 0
spLoop:
    cmp ecx, entryCount
    jge spNotFound
    mov eax, ecx
    imul eax, FIELD_LEN
    lea edx, websites[eax]
    mov eax, OFFSET searchBuf
    call StrCompare
    jz spFound
    inc ecx
    jmp spLoop
spFound:
    call PinLock
    call Clrscr
    mov eax, ecx
    imul eax, FIELD_LEN
    mov esi, eax

    mov edx, OFFSET divider
    call WriteString
    mov edx, OFFSET websitePrompt
    call WriteString
    lea edx, websites[esi]
    call WriteString
    call Crlf
    mov edx, OFFSET userPrompt
    call WriteString
    lea edx, usernames[esi]
    call WriteString
    call Crlf

    lea esi, passwords[esi]
    lea edi, tempPass
    mov ecx, FIELD_LEN
    rep movsb
    mov BYTE PTR tempPass[FIELD_LEN-1], 0

    lea esi, tempPass
    mov bl, CAESAR_SHIFT
    call CaesarDecrypt
    call XorCrypt

    mov edx, OFFSET passPrompt
    call WriteString
    mov edx, OFFSET tempPass
    call WriteString
    call Crlf
    jmp spDone
spNotFound:
    mov edx, OFFSET notFoundStr
    call WriteString
spDone:
    mov edx, OFFSET pressKey
    call WriteString
    call ReadChar
    popa
    ret
SearchPassword ENDP

; ... (Keep your original EncryptMenu, XorCrypt, CaesarEncrypt, CaesarDecrypt, GeneratePassword)

EncryptMenu PROC
    pusha
    mov edx, OFFSET encChoice
    call WriteString
    call ReadChar
    call Crlf
    cmp al, '1'
    je doEnc
    cmp al, '2'
    je doDec
    jmp emDone
doEnc:
    mov edx, OFFSET encPrompt
    call WriteString
    mov edx, OFFSET encBuf
    mov ecx, FIELD_LEN*2-1
    call ReadString
    mov esi, OFFSET encBuf
    call XorCrypt
    mov bl, CAESAR_SHIFT
    call CaesarEncrypt
    mov edx, OFFSET encResult
    call WriteString
    mov edx, OFFSET encBuf
    call WriteString
    call Crlf
    jmp emDone
doDec:
    mov edx, OFFSET decPrompt
    call WriteString
    mov edx, OFFSET encBuf
    mov ecx, FIELD_LEN*2-1
    call ReadString
    mov esi, OFFSET encBuf
    mov bl, CAESAR_SHIFT
    call CaesarDecrypt
    call XorCrypt
    mov edx, OFFSET decResult
    call WriteString
    mov edx, OFFSET encBuf
    call WriteString
    call Crlf
emDone:
    mov edx, OFFSET pressKey
    call WriteString
    call ReadChar
    popa
    ret
EncryptMenu ENDP

; (Add the rest of your original procedures: XorCrypt, CaesarEncrypt, CaesarDecrypt, GeneratePassword)

XorCrypt PROC
    push esi
    push eax
xorLoop:
    mov al, [esi]
    cmp al, 0
    je xorDone
    xor al, XOR_KEY
    mov [esi], al
    inc esi
    jmp xorLoop
xorDone:
    pop eax
    pop esi
    ret
XorCrypt ENDP

CaesarEncrypt PROC
    pushad
ceLoop:
    mov al, [esi]
    cmp al, 0
    je ceDone
    cmp al, 'A'
    jl ceLower
    cmp al, 'Z'
    jg ceLower
    sub al, 'A'
    add al, bl
    cmp al, 26
    jl ceU1
    sub al, 26
ceU1:
    add al, 'A'
    jmp ceStore
ceLower:
    cmp al, 'a'
    jl ceStore
    cmp al, 'z'
    jg ceStore
    sub al, 'a'
    add al, bl
    cmp al, 26
    jl ceL1
    sub al, 26
ceL1:
    add al, 'a'
ceStore:
    mov [esi], al
    inc esi
    jmp ceLoop
ceDone:
    popad
    ret
CaesarEncrypt ENDP

CaesarDecrypt PROC
    pushad
cdLoop:
    mov al, [esi]
    cmp al, 0
    je cdDone
    cmp al, 'A'
    jl cdLower
    cmp al, 'Z'
    jg cdLower
    sub al, 'A'
    cmp al, bl
    jge cdU1
    add al, 26
cdU1:
    sub al, bl
    add al, 'A'
    jmp cdStore
cdLower:
    cmp al, 'a'
    jl cdStore
    cmp al, 'z'
    jg cdStore
    sub al, 'a'
    cmp al, bl
    jge cdL1
    add al, 26
cdL1:
    sub al, bl
    add al, 'a'
cdStore:
    mov [esi], al
    inc esi
    jmp cdLoop
cdDone:
    popad
    ret
CaesarDecrypt ENDP

GeneratePassword PROC
    pusha
    mov edx, OFFSET genLenPrompt
    call WriteString
    call ReadInt
    cmp eax, 8
    jge gpMin
    mov eax, 8
gpMin:
    cmp eax, 20
    jle gpMax
    mov eax, 20
gpMax:
    mov genLength, eax
    mov edx, OFFSET genPrompt
    call WriteString
    call Randomize
    mov edi, OFFSET genBuf
    mov ecx, genLength
    mov ebx, 0
gpLoop:
    mov eax, 4
    call RandomRange
    cmp eax, 0
    je useLower
    cmp eax, 1
    je useUpper
    cmp eax, 2
    je useDigit
    jmp useSpecial
useLower:
    mov eax, 26
    call RandomRange
    mov al, lowerChars[eax]
    jmp save
useUpper:
    mov eax, 26
    call RandomRange
    mov al, upperChars[eax]
    jmp save
useDigit:
    mov eax, 10
    call RandomRange
    mov al, digitChars[eax]
    jmp save
useSpecial:
    mov eax, 8
    call RandomRange
    mov al, specialChars[eax]
save:
    mov [edi+ebx], al
    inc ebx
    cmp ebx, ecx
    jl gpLoop
    mov BYTE PTR [edi+ebx], 0
    mov edx, OFFSET genResult
    call WriteString
    mov edx, OFFSET genBuf
    call WriteString
    call Crlf
    mov edx, OFFSET pressKey
    call WriteString
    call ReadChar
    popa
    ret
GeneratePassword ENDP

END main