const express = require('express');
const router = express.Router();

// Halaman statis. Tidak ada query DB, tidak ada state — cukup render.
// Author + repo URL di-hardcode di sini (bukan di client) supaya tidak
// tercecer di banyak tempat. Git URL punya pengguna, bukan rahasia.
router.get('/', (req, res) => {
  res.render('about/index', {
    GIT_URL: 'https://github.com/torpedoliar',
    AUTHOR: 'Yohanes Octavian Rizky'
  });
});

module.exports = router;
