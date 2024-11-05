const commands = [
    "./share_the_knowledge",
    "./exploit_breaking_stuffs",
	"sh community && ./be_safe",
	"./run --privacy",
	"./reuse && ./recycle"
  ];
  
  let commandIndex = 0;
  let charIndex = 0;
  let isDeleting = false;
  
  const typingSpeed = 200; // velocità di digitazione
  const deletingSpeed = 50; // velocità di cancellazione
  const delayBetweenCommands = 3000; // ritardo tra i comandi
  
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