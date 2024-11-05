const commands = [
    "./share_the_knowledge",
    "./exploit_breaking_stuffs",
    "sh community && ./be_safe",
    "./run --privacy",
    "./reuse || ./recycle"
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
  
    if (!isDeleting) {
      // Aggiungi un carattere alla volta al testo
      terminalText.textContent = currentCommand.slice(0, charIndex++);
      
      // Quando abbiamo digitato tutto il comando
      if (charIndex > currentCommand.length) {
        isDeleting = true;
        setTimeout(typeCommand, delayBetweenCommands); // Aspetta prima di cancellare
      } else {
        setTimeout(typeCommand, typingSpeed); // Continua a digitare
      }
    } else {
      // Cancellazione del testo
      terminalText.textContent = currentCommand.slice(0, charIndex--);
      
      // Quando tutto il testo è stato cancellato
      if (charIndex < 0) {
        isDeleting = false;
        commandIndex = (commandIndex + 1) % commands.length; // Passa al comando successivo
        charIndex = 0; // Reset dell'indice dei caratteri per il prossimo comando
        terminalText.textContent = ""; // Nascondi il testo prima di iniziare a digitare il prossimo comando
        setTimeout(typeCommand, typingSpeed); // Inizia a digitare il nuovo comando
      } else {
        setTimeout(typeCommand, deletingSpeed); // Continua a cancellare
      }
    }
  }
  
  // Avvia l'effetto di digitazione al caricamento della pagina
  document.addEventListener("DOMContentLoaded", typeCommand);