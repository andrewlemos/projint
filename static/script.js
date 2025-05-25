console.log("Sistema de Alertas da Defesa Civil carregado!");

// Formata CEP (12345678 → 12345-678)
function formatarCEP(input) {
    let valor = input.value.replace(/\D/g, '');
    if (valor.length > 5) {
        valor = valor.substring(0, 5) + '-' + valor.substring(5, 8);
    }
    input.value = valor;
}

// Formata telefone (19998107110 → (19)99810-7110)
function formatarTelefone(input) {
    let valor = input.value.replace(/\D/g, '');
    if (valor.length > 2) {
        valor = '(' + valor.substring(0, 2) + ')' + valor.substring(2, 7) + 
               (valor.length > 7 ? '-' + valor.substring(7, 11) : '');
    }
    input.value = valor;
}


// Sistema de alertas sonoros 
{% if novos_alertas %}
    document.addEventListener('DOMContentLoaded', function() {
        const alertSound = document.getElementById('alertSound');
        const toggleBtn = document.getElementById('toggleSound');
        let isMuted = localStorage.getItem('alertMuted') === 'true';
        
        // Configura estado inicial
        if (isMuted) {
            alertSound.muted = true;
            toggleBtn.innerHTML = '<i class="fas fa-volume-mute"></i> Ativar Alerta';
        }
        
        // Tenta tocar o som
        function playAlert() {
            alertSound.play()
                .then(() => console.log("Alerta sonoro tocado"))
                .catch(e => {
                    console.log("Reprodução automática bloqueada:", e);
                    // Mostra um botão para permitir o som
                    toggleBtn.style.display = 'block';
                });
        }
        
        // Toca apenas se não estiver silenciado
        if (!isMuted) {
            setTimeout(playAlert, 1000);
        }
        
        // Silenciar/ativar
        toggleBtn.addEventListener('click', function() {
            isMuted = !isMuted;
            alertSound.muted = isMuted;
            localStorage.setItem('alertMuted', isMuted);
            
            if (isMuted) {
                toggleBtn.innerHTML = '<i class="fas fa-volume-mute"></i> Ativar Alerta';
                alertSound.pause();
            } else {
                toggleBtn.innerHTML = '<i class="fas fa-volume-up"></i> Silenciar Alerta';
                playAlert();
            }
        });
    });
{% endif %}