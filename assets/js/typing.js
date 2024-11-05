const commands = [
    "cdq  ; xor edx",
    "mul edx",
	"lea ecx, [eax]",
	"mov esi, 0x68732f2f",
	"mov edi, 0x6e69622f",
	"push ecx                ; push NULL in stack",
	"push esi",
	"push edi                ; push hs/nib// in stack",
	"lea ebx, [esp]          ; load stack pointer to ebx",
	"mov al, 0xb             ; load execve in eax",
	"int 0x80"
  ];
  
  let commandIndex = 0;
  let charIndex = 0;
  let isDeleting = false;
  
  const typingSpeed = 100; // velocità di digitazione
  const deletingSpeed = 50; // velocità di cancellazione
  const delayBetweenCommands = 2000; // ritardo tra i comandi
  
  function typeCommand() {
    const terminalText = document.getElementById("typing-text");
    const currentCommand = commands[commandIndex];
  
    // Aggiunge o rimuove caratteri in base allo stato
    if (!isDeleting) {
      terminalText.textContent = currentCommand.slice(0, charIndex++);
      if (charIndex > currentCommand.length) {
        isDeleting = true;
        setTimeout(typeCommand, delayBetweenCommands);
      } else {
        setTimeout(typeCommand, typingSpeed);
      }
    } else {
      terminalText.textContent = currentCommand.slice(0, charIndex--);
      if (charIndex < 0) {
        isDeleting = false;
        commandIndex = (commandIndex + 1) % commands.length;
        setTimeout(typeCommand, typingSpeed);
      } else {
        setTimeout(typeCommand, deletingSpeed);
      }
    }
  }
  
  // Avvia l'effetto di typing al caricamento della pagina
  document.addEventListener("DOMContentLoaded", typeCommand);