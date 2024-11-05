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
  
  const typingSpeed = 100; // velocità di digitazione
  const deletingSpeed = 50; // velocità di cancellazione
  const delayBetweenCommands = 2000; // ritardo tra i comandi
  
  function typeCommand() {
    const terminalText = document.getElementById("typing-text");
    const currentCommand = commands[commandIndex];
  
    if (!isDeleting) {
      // Rendi visibile il testo quando inizia a digitare
      terminalText.textContent = currentCommand.slice(0, charIndex++);
      
      // Se abbiamo finito di digitare, inizia a cancellare dopo un ritardo
      if (charIndex > currentCommand.length) {
        isDeleting = true;
        setTimeout(typeCommand, delayBetweenCommands);
      } else {
        setTimeout(typeCommand, typingSpeed);
      }
    } else {
      // Iniziamo a cancellare il testo
      terminalText.textContent = currentCommand.slice(0, charIndex--);
      
      // Se abbiamo finito di cancellare, inizia il prossimo comando
      if (charIndex < 0) {
        isDeleting = false;
        commandIndex = (commandIndex + 1) % commands.length;
  
        // Prima di digitare il prossimo comando, assicuriamoci che il testo sia vuoto
        terminalText.textContent = ""; // Nascondiamo il testo prima di iniziare il prossimo comando
        charIndex = 0; // Ripristina l'indice del carattere per il nuovo comando
        setTimeout(typeCommand, typingSpeed);
      } else {
        setTimeout(typeCommand, deletingSpeed);
      }
    }
  }
  
  // Avvia l'effetto di typing al caricamento della pagina
  document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("typing-text").textContent = ""; // Inizializza come vuoto
    typeCommand();
  });