<?php
class VoteAsses {
    // Simulasi data tugas LMS
    private $tugasLMSData = [
        '28982972' => true,  // NIM => Status tugas (true = sudah selesai, false = belum selesai)
        '287997287' => false
    ];

    /**
     * @param string $nisn
     * @return string
     */
    public function getVote($nisn) {
        // Cek apakah NIM ada dalam data
        if (array_key_exists($nisn, $this->tugasLMSData)) {
            $tugasLMS = $this->tugasLMSData[$nisn];
            if ($tugasLMS) {
                return "Silahkan melakukan voting!";
            } else {
                return "Anda harus menyelesaikan tugas sebelum memberikan suara.";
            }
        } else {
            return "NIM tidak dikenal.";
        }
    }


    /**
     * @return array 
     *
     */
    public function getHistories() {
        $a = new stdClass;
        $a->nim ='32454161';
        $a->pilihan ='3';

        $b = new stdClass;
        $b->nim ='32928287';
        $b->pilihan='2';

        $histories = [$a,$b];
        return $histories;
    }
    //  /**
    //  * Add a vote history entry
    //  * @param string $vote
    //  * @return void
    //  */
    // public function addHistory($vote) {
    //     $this->histories[] = $vote;
    // }

    // /**
    //  * @return string
    //  */
    // public function getHistories() {
    //     $historyString = "";
    //     foreach ($this->histories as $history) {
    //         $historyString .= $history . "\n";
    //     }
    //     return $historyString;
    // }
}

