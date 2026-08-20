// State
let apiKey = localStorage.getItem('gmaps_api_key') || '';
let searchResults = [];
let savedContacts = JSON.parse(localStorage.getItem('gmaps_saved_contacts') || '[]');
let currentTypeFilter = 'all';
let currentPage = 1;
const resultsPerPage = 10;

// Toast notification
function showToast(message, type = 'info') {
    let toast = document.querySelector('.toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

// Check API Key
function checkApiKey() {
    if (apiKey) {
        document.getElementById('apiKeySetup').style.display = 'none';
        document.getElementById('searchSection').style.display = 'block';
        return true;
    }
    return false;
}

// Save API Key
function saveApiKey() {
    const input = document.getElementById('apiKeyInput');
    const key = input.value.trim();
    if (!key) {
        showToast('Masukkan API Key yang valid', 'error');
        return;
    }
    apiKey = key;
    localStorage.setItem('gmaps_api_key', key);
    document.getElementById('apiKeySetup').style.display = 'none';
    document.getElementById('searchSection').style.display = 'block';
    showToast('API Key berhasil disimpan!', 'success');
}

// Set Type Filter
function setTypeFilter(type, el) {
    currentTypeFilter = type;
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    el.classList.add('active');
    if (searchResults.length > 0) {
        filterAndDisplayResults();
    }
}

// Filter and Display Results
function filterAndDisplayResults() {
    currentPage = 1;
    renderResults();
}

// Search Businesses
async function searchBusinesses() {
    const query = document.getElementById('searchInput').value.trim();
    if (!query) {
        showToast('Masukkan kata kunci pencarian', 'error');
        return;
    }

    if (!apiKey) {
        showToast('Masukkan API Key terlebih dahulu', 'error');
        return;
    }

    const loading = document.getElementById('loading');
    const error = document.getElementById('error');
    const results = document.getElementById('results');
    const searchBtn = document.getElementById('searchBtn');

    // Show loading
    loading.style.display = 'block';
    error.style.display = 'none';
    results.innerHTML = '';
    searchBtn.disabled = true;
    searchBtn.innerHTML = '<span class="spinner" style="width:20px;height:20px;border-width:2px;"></span>';

    try {
        // Text Search
        const baseUrl = 'https://maps.googleapis.com/maps/api/place/textsearch/json';
        let url = `${baseUrl}?query=${encodeURIComponent(query)}&key=${apiKey}&language=id`;
        
        if (currentTypeFilter !== 'all') {
            url += `&type=${currentTypeFilter}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (data.status === 'REQUEST_DENIED') {
            throw new Error(`API Error: ${data.error_message || 'Permission denied'}`);
        }

        if (!data.results || data.results.length === 0) {
            searchResults = [];
            renderResults();
            return;
        }

        // Get details for each place (including phone numbers)
        searchResults = await Promise.all(
            data.results.map(async (place) => {
                try {
                    const detailUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${place.place_id}&fields=formatted_phone_number,website,url,opening_hours&key=${apiKey}&language=id`;
                    const detailRes = await fetch(detailUrl);
                    const detailData = await detailRes.json();
                    
                    return {
                        id: place.place_id,
                        name: place.name,
                        address: place.formatted_address,
                        rating: place.rating || 0,
                        totalRatings: place.user_ratings_total || 0,
                        types: place.types || [],
                        phone: detailData.result?.formatted_phone_number || '',
                        website: detailData.result?.website || '',
                        mapsUrl: detailData.result?.url || `https://maps.google.com/?place_id=${place.place_id}`,
                        isOpen: detailData.result?.opening_hours?.open_now,
                        location: place.geometry?.location
                    };
                } catch (err) {
                    return {
                        id: place.place_id,
                        name: place.name,
                        address: place.formatted_address,
                        rating: place.rating || 0,
                        totalRatings: place.user_ratings_total || 0,
                        types: place.types || [],
                        phone: '',
                        website: '',
                        mapsUrl: `https://maps.google.com/?place_id=${place.place_id}`,
                        isOpen: null,
                        location: place.geometry?.location
                    };
                }
            })
        );

        currentPage = 1;
        renderResults();

    } catch (err) {
        console.error('Search error:', err);
        error.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${err.message}`;
        error.style.display = 'flex';
    } finally {
        loading.style.display = 'none';
        searchBtn.disabled = false;
        searchBtn.innerHTML = '<i class="fas fa-search"></i> Cari';
    }
}

// Render Results
function renderResults() {
    const container = document.getElementById('results');
    const paginationEl = document.getElementById('pagination');
    
    let filtered = searchResults;
    if (currentTypeFilter !== 'all') {
        filtered = searchResults.filter(biz => 
            biz.types.some(t => t.includes(currentTypeFilter))
        );
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-search"></i>
                <h3>Tidak Ada Hasil</h3>
                <p>Coba kata kunci atau filter yang berbeda</p>
            </div>
        `;
        paginationEl.style.display = 'none';
        return;
    }

    // Pagination
    const totalPages = Math.ceil(filtered.length / resultsPerPage);
    const startIdx = (currentPage - 1) * resultsPerPage;
    const pageResults = filtered.slice(startIdx, startIdx + resultsPerPage);

    let html = `
        <div class="results-header">
            <span class="results-count">Ditemukan ${filtered.length} bisnis</span>
            <button class="export-btn" onclick="exportToCSV()">
                <i class="fas fa-download"></i> Export CSV
            </button>
        </div>
    `;

    pageResults.forEach(biz => {
        const isSaved = savedContacts.some(c => c.id === biz.id);
        const stars = '★'.repeat(Math.floor(biz.rating)) + 
                     (biz.rating % 1 >= 0.5 ? '½' : '') +
                     '☆'.repeat(5 - Math.ceil(biz.rating));

        html += `
            <div class="business-card">
                ${isSaved ? '<span class="saved-badge"><i class="fas fa-bookmark"></i> Tersimpan</span>' : ''}
                <div class="business-name">${escapeHtml(biz.name)}</div>
                <div class="business-rating">
                    <span class="stars">${stars}</span>
                    <span class="rating-text">${biz.rating} (${biz.totalRatings} ulasan)</span>
                    ${biz.isOpen !== null ? `
                        <span class="status-badge ${biz.isOpen ? 'status-open' : 'status-closed'}">
                            <i class="fas fa-${biz.isOpen ? 'door-open' : 'door-closed'}"></i>
                            ${biz.isOpen ? 'Buka' : 'Tutup'}
                        </span>
                    ` : ''}
                </div>
                <div class="business-info">
                    <div class="info-row">
                        <i class="fas fa-map-marker-alt"></i>
                        <span>${escapeHtml(biz.address)}</span>
                    </div>
                    ${biz.phone ? `
                        <div class="info-row">
                            <i class="fas fa-phone"></i>
                            <a href="tel:${biz.phone}" class="phone-link">
                                ${escapeHtml(biz.phone)}
                                <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(biz.phone)}', event)">
                                    <i class="fas fa-copy"></i> Salin
                                </button>
                            </a>
                        </div>
                    ` : `
                        <div class="info-row">
                            <i class="fas fa-phone" style="color: #cbd5e1;"></i>
                            <span style="color: #cbd5e1;">Nomor tidak tersedia</span>
                        </div>
                    `}
                    ${biz.website ? `
                        <div class="info-row">
                            <i class="fas fa-globe"></i>
                            <a href="${escapeHtml(biz.website)}" target="_blank" style="color: #667eea;">
                                ${escapeHtml(new URL(biz.website).hostname)}
                            </a>
                        </div>
                    ` : ''}
                </div>
                <div class="actions-row">
                    <a href="${escapeHtml(biz.mapsUrl)}" target="_blank" class="action-btn maps-btn">
                        <i class="fas fa-map"></i> Lihat di Maps
                    </a>
                    <button class="action-btn save-btn" onclick='saveContact(${JSON.stringify(biz).replace(/'/g, "&#39;")})'>
                        <i class="fas fa-bookmark"></i> ${isSaved ? 'Tersimpan' : 'Simpan'}
                    </button>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;

    // Render pagination
    if (totalPages > 1) {
        let paginationHtml = '';
        for (let i = 1; i <= totalPages; i++) {
            paginationHtml += `
                <button class="page-btn ${i === currentPage ? 'active' : ''}" 
                        onclick="goToPage(${i})">${i}</button>
            `;
        }
        paginationEl.innerHTML = paginationHtml;
        paginationEl.style.display = 'flex';
    } else {
        paginationEl.style.display = 'none';
    }
}

// Go to Page
function goToPage(page) {
    currentPage = page;
    renderResults();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Copy to Clipboard
function copyToClipboard(text, event) {
    event.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
        showToast('Nomor berhasil disalin!', 'success');
    }).catch(() => {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showToast('Nomor berhasil disalin!', 'success');
    });
}

// Save Contact
function saveContact(biz) {
    const idx = savedContacts.findIndex(c => c.id === biz.id);
    if (idx > -1) {
        savedContacts.splice(idx, 1);
        showToast('Kontak dihapus dari simpanan', 'info');
    } else {
        savedContacts.push({
            ...biz,
            savedAt: new Date().toISOString()
        });
        showToast('Kontak berhasil disimpan!', 'success');
    }
    localStorage.setItem('gmaps_saved_contacts', JSON.stringify(savedContacts));
    renderResults();
    renderSavedContacts();
}

// Render Saved Contacts
function renderSavedContacts() {
    const container = document.getElementById('savedContacts');
    const list = document.getElementById('savedList');
    
    if (savedContacts.length === 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'block';
    list.innerHTML = savedContacts.map(biz => `
        <div class="business-card" style="margin-bottom: 12px;">
            <div class="business-name" style="font-size: 16px;">${escapeHtml(biz.name)}</div>
            <div class="business-info">
                <div class="info-row">
                    <i class="fas fa-map-marker-alt"></i>
                    <span>${escapeHtml(biz.address)}</span>
                </div>
                ${biz.phone ? `
                    <div class="info-row">
                        <i class="fas fa-phone"></i>
                        <a href="tel:${biz.phone}" class="phone-link">
                            ${escapeHtml(biz.phone)}
                            <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(biz.phone)}', event)">
                                <i class="fas fa-copy"></i>
                            </button>
                        </a>
                    </div>
                ` : ''}
            </div>
            <div class="actions-row">
                <button class="action-btn save-btn" onclick="removeSaved('${biz.id}')" style="background: rgba(239,68,68,0.1); color: #ef4444;">
                    <i class="fas fa-trash"></i> Hapus
                </button>
            </div>
        </div>
    `).join('');
}

// Remove Saved Contact
function removeSaved(id) {
    savedContacts = savedContacts.filter(c => c.id !== id);
    localStorage.setItem('gmaps_saved_contacts', JSON.stringify(savedContacts));
    renderSavedContacts();
    renderResults();
    showToast('Kontak dihapus', 'info');
}

// Export to CSV
function exportToCSV() {
    if (searchResults.length === 0) {
        showToast('Tidak ada data untuk di-export', 'error');
        return;
    }

    let csv = 'Nama,Alamat,No HP,Rating,Ulasan,Website\n';
    searchResults.forEach(biz => {
        csv += `"${biz.name}","${biz.address}","${biz.phone}","${biz.rating}","${biz.totalRatings}","${biz.website}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `bisnis_${new Date().toISOString().slice(0,10)}.csv`;
    link.click();

    showToast('File CSV berhasil di-download!', 'success');
}

// Escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Handle Enter key
document.getElementById('searchInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        searchBusinesses();
    }
});

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkApiKey();
    renderSavedContacts();
});
