$(()=>{
    $('#his').on ('click',()=>{
        $.ajax({
            url: 'client-history.php',
            method :'POST'
        }).done((histories)=>{
            console.log(histories);
            let html ='';
            for(let h of histories) {
                html += `<p> ${h.nim}`;
                html += `-${h.pilihan}</p>`;
            }
            $('#output').html(html);
        });
    });

    $('#vt').on ('click',()=>{
        $.ajax({
            url: 'client-vote.php',
            method :'POST',
            data:{tugasLMS :true}
            
        }).done((vote)=>{
            console.log(vote);
            let html ='';
            if (vote === 'Silahkan melakukan voting!') {
                html += '<p>Silahkan melakukan voting!</p>';
            } else {
                html += '<p>Anda harus menyelesaikan tugas sebelum memberikan suara.</p>';
            }
            $('#output').html(html);
        });
    });
});