package com.seedboxtuga.ipscore

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.text.Html
import android.text.method.LinkMovementMethod
import android.view.LayoutInflater
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.lifecycleScope
import com.seedboxtuga.ipscore.databinding.ActivityMainBinding
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class ApiResult(val apiName: String, val data: Map<String, Any>)
data class CachedResult(val timestamp: Long, val results: List<ApiResult>)

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var sharedPreferences: SharedPreferences
    private var currentResults: List<ApiResult> = emptyList()

    private val apiProviders = mapOf(
        "ipqualityscore" to "IPQualityScore",
        "abuseipdb" to "AbuseIPDB",
        "virustotal" to "VirusTotal",
        "ipdata" to "IPData",
        "fraudlogix" to "Fraudlogix",
        "ipgeolocation" to "IPGeolocation",
        "pulsedive" to "Pulsedive",
        "ipapi.is" to "ipapi.is"
    )
    private var selectedApiKeyName = apiProviders.keys.first()

    private val keylessApis = setOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        sharedPreferences = getSharedPreferences("ApiKeys", Context.MODE_PRIVATE)

        setupSpinner()
        setupSaveButton()
        setupHelpButton()
        setupShareButton()
        setupHistoryButton()

        binding.refreshButton.setOnClickListener {
            fetchAllScores()
        }

        fetchAllScores(useCurrentUserIp = true)
    }

    private fun setupSpinner() {
        val apiDisplayNames = apiProviders.values.toList()
        val adapter = ArrayAdapter(this, R.layout.spinner_item_layout, apiDisplayNames)
        adapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        binding.apiSpinner.adapter = adapter

        binding.apiSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?, position: Int, id: Long) {
                selectedApiKeyName = apiProviders.keys.toList()[position]
                loadApiKeyForSelectedProvider()
                toggleApiKeyInputVisibility()
            }

            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }

    private fun setupSaveButton() {
        binding.saveKeyButton.setOnClickListener {
            val apiKey = binding.apiKeyEditText.text.toString().trim()
            if (apiKey.isNotEmpty()) {
                saveApiKey(selectedApiKeyName, apiKey)
                Toast.makeText(this, "${apiProviders[selectedApiKeyName]} key saved!", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "API key cannot be empty.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun setupHelpButton() {
        binding.helpButton.setOnClickListener {
            val message = Html.fromHtml(getString(R.string.about_description_with_links), Html.FROM_HTML_MODE_LEGACY)
            val dialog = AlertDialog.Builder(this)
                .setTitle(getString(R.string.about_title))
                .setMessage(message)
                .setPositiveButton("OK") { dialog, _ ->
                    dialog.dismiss()
                }
                .create()

            dialog.show()
            (dialog.findViewById(android.R.id.message) as? TextView)?.movementMethod = LinkMovementMethod.getInstance()
        }
    }

    private fun setupShareButton() {
        binding.shareButton.setOnClickListener {
            if (currentResults.isEmpty()) {
                Toast.makeText(this, "No results to share.", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val shareableText = buildShareableString()
            val sendIntent: Intent = Intent().apply {
                action = Intent.ACTION_SEND
                putExtra(Intent.EXTRA_TEXT, shareableText)
                type = "text/plain"
            }

            val shareIntent = Intent.createChooser(sendIntent, null)
            startActivity(shareIntent)
        }
    }

    private fun setupHistoryButton() {
        binding.historyButton.setOnClickListener {
            showHistoryDialog()
        }
    }

    private fun showHistoryDialog() {
        val history = getHistory()
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_history, null)
        val listView = dialogView.findViewById<ListView>(R.id.historyListView)

        val adapter = ArrayAdapter(this, R.layout.history_item, R.id.historyItemTextView, history)
        listView.adapter = adapter

        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.history_title))
            .setView(dialogView)
            .setNegativeButton("Close") { dialog, _ ->
                dialog.dismiss()
            }
            .create()

        listView.setOnItemClickListener { _, _, position, _ ->
            val selectedIp = history[position]
            binding.manualIpEditText.setText(selectedIp)
            fetchAllScores()
            dialog.dismiss()
        }

        dialog.show()
    }

    private fun buildShareableString(): String {
        val report = StringBuilder()
        val ipAddressText = binding.ipAddressText.text.toString()
        report.append("IP Reputation Report for: $ipAddressText\n\n")

        currentResults.forEach { result ->
            report.append("--- ${result.apiName} ---\n")
            result.data.forEach { (key, value) ->
                report.append("$key: $value\n")
            }
            report.append("\n")
        }
        return report.toString()
    }

    private fun loadApiKeyForSelectedProvider() {
        val savedKey = getApiKey(selectedApiKeyName)
        binding.apiKeyEditText.setText(savedKey)
        binding.apiKeyLayout.hint = "${apiProviders[selectedApiKeyName]} API Key"
    }

    private fun toggleApiKeyInputVisibility() {
        if (keylessApis.contains(selectedApiKeyName)) {
            binding.apiKeyLayout.visibility = View.GONE
            binding.saveKeyButton.visibility = View.GONE
        } else {
            binding.apiKeyLayout.visibility = View.VISIBLE
            binding.saveKeyButton.visibility = View.VISIBLE
        }
    }

    private fun fetchAllScores(useCurrentUserIp: Boolean = false) {
        binding.progressBar.visibility = View.VISIBLE
        binding.resultsContainer.removeAllViews()
        binding.errorText.visibility = View.GONE
        binding.refreshButton.isEnabled = false
        binding.offlineStatusText.visibility = View.GONE
        currentResults = emptyList()

        lifecycleScope.launch {
            val manualIp = binding.manualIpEditText.text.toString().trim()
            val ipToProcess: String

            if (!isNetworkAvailable()) {
                // OFFLINE LOGIC
                ipToProcess = if (manualIp.isNotEmpty() && isValidIpAddress(manualIp)) {
                    manualIp
                } else {
                    getHistory().firstOrNull() ?: ""
                }

                if (ipToProcess.isNotEmpty()) {
                    val cachedResult = getResultFromCache(ipToProcess)
                    if (cachedResult != null) {
                        withContext(Dispatchers.Main) {
                            binding.ipAddressText.text = getString(R.string.checking_ip, ipToProcess)
                            updateUiWithAllResults(cachedResult.results, cachedResult.timestamp)
                        }
                    } else {
                        showError("You are offline and no cached data is available for this IP.")
                    }
                } else {
                    showError("You are offline. Please enter an IP to check the cache or connect to the internet.")
                }
                return@launch
            }

            // ONLINE LOGIC
            try {
                if (useCurrentUserIp || manualIp.isEmpty()) {
                    ipToProcess = getPublicIp()
                    withContext(Dispatchers.Main) {
                        binding.ipAddressText.text = getString(R.string.your_ip, ipToProcess)
                    }
                } else {
                    if (isValidIpAddress(manualIp)) {
                        ipToProcess = manualIp
                        withContext(Dispatchers.Main) {
                            binding.ipAddressText.text = getString(R.string.checking_ip, ipToProcess)
                        }
                    } else {
                        showError("Invalid IP address format.")
                        return@launch
                    }
                }

                saveToHistory(ipToProcess)

                val apiFetchJobs = apiProviders.keys.map { apiKeyName ->
                    async(Dispatchers.IO) {
                        val apiKey = getApiKey(apiKeyName)
                        if (keylessApis.contains(apiKeyName) || !apiKey.isNullOrEmpty()) {
                            try {
                                val data = getScoreForIp(apiKeyName, ipToProcess, apiKey)
                                ApiResult(apiProviders[apiKeyName]!!, data)
                            } catch (e: Exception) {
                                null
                            }
                        } else null
                    }
                }

                val results = apiFetchJobs.awaitAll().filterNotNull()
                currentResults = results
                saveResultsToCache(ipToProcess, results)

                if (results.isEmpty()) {
                    showError("No API keys saved or all requests failed.")
                } else {
                    updateUiWithAllResults(results)
                }

            } catch (e: Exception) {
                showError(e.message ?: "An error occurred while fetching IP.")
            }
        }
    }

    private fun isValidIpAddress(ip: String): Boolean {
        return try {
            InetAddress.getByName(ip)
            true
        } catch (e: Exception) {
            false
        }
    }

    private suspend fun getPublicIp(): String = withContext(Dispatchers.IO) {
        val url = URL("https://api.ipify.org?format=json")
        val connection = url.openConnection() as HttpURLConnection
        try {
            val response = connection.inputStream.bufferedReader().use { it.readText() }
            JSONObject(response).getString("ip")
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun getScoreForIp(apiKeyName: String, ip: String, apiKey: String?): Map<String, Any> = withContext(Dispatchers.IO) {
        val url = when (apiKeyName) {
            "ipqualityscore" -> "https://ipqualityscore.com/api/json/ip/$apiKey/$ip"
            "abuseipdb" -> "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip"
            "virustotal" -> "https://www.virustotal.com/api/v3/ip_addresses/$ip"
            "ipdata" -> "https://api.ipdata.co/$ip?api-key=$apiKey&fields=country_code,asn,is_vpn,threat,trust_score,threat_score"
            "fraudlogix" -> "https://iplist.fraudlogix.com/v5?ip=$ip"
            "ipgeolocation" -> "https://api.ipgeolocation.io/ipgeo?apiKey=$apiKey&ip=$ip&fields=security"
            "pulsedive" -> "https://pulsedive.com/api/info.php?indicator=$ip&pretty=1"
            "ipapi.is" -> "https://api.ipapi.is?q=$ip"
            else -> throw Exception("Invalid API selected")
        }

        val headers = when (apiKeyName) {
            "abuseipdb" -> mapOf("Key" to apiKey!!, "Accept" to "application/json")
            "virustotal" -> mapOf("x-apikey" to apiKey!!)
            "fraudlogix" -> mapOf("x-api-key" to apiKey!!)
            "pulsedive" -> mapOf("Authorization" to "Bearer $apiKey")
            "ipapi.is" -> mapOf("X-API-KEY" to apiKey!!)
            else -> emptyMap()
        }

        val connection = URL(url).openConnection() as HttpURLConnection
        headers.forEach { (k, v) -> connection.setRequestProperty(k, v) }

        try {
            if (connection.responseCode == HttpURLConnection.HTTP_OK) {
                val response = connection.inputStream.bufferedReader().use { it.readText() }
                parseApiResponse(apiKeyName, response)
            } else {
                throw Exception("$apiKeyName API Error: ${connection.responseMessage}")
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun parseApiResponse(apiKeyName: String, response: String): Map<String, Any> {
        val json = JSONObject(response)
        val data = mutableMapOf<String, Any>()

        when (apiKeyName) {
            "ipqualityscore" -> {
                data["Fraud Score"] = json.optInt("fraud_score", 0)
                data["Country"] = json.optString("country_code", "N/A")
                data["ISP"] = json.optString("ISP", "N/A")
                data["VPN"] = json.optBoolean("vpn")
                data["Tor"] = json.optBoolean("tor")
                data["Proxy"] = json.optBoolean("proxy")
            }
            "abuseipdb" -> {
                val abuseData = json.getJSONObject("data")
                data["Abuse Score"] = abuseData.optInt("abuseConfidenceScore", 0)
                data["Usage Type"] = abuseData.optString("usageType", "N/A")
                data["Is Tor"] = abuseData.optBoolean("isTor")
                data["Total Reports"] = abuseData.optInt("totalReports", 0)
                data["Num Distinct Users"] = abuseData.optInt("numDistinctUsers", 0)
                data["Last Reported At"] = abuseData.optString("lastReportedAt", "N/A")
            }
            "virustotal" -> {
                val attributes = json.getJSONObject("data").getJSONObject("attributes")
                val stats = attributes.getJSONObject("last_analysis_stats")
                data["Reputation"] = attributes.optInt("reputation", 0)
                data["Malicious"] = stats.optInt("malicious", 0)
                data["Suspicious"] = stats.optInt("suspicious", 0)
                data["ISP"] = attributes.optString("as_owner", "N/A")
            }
            "ipdata" -> {
                val threat = json.optJSONObject("threat") ?: JSONObject()
                data["Trust Score"] = json.optInt("trust_score", 0)
                data["Threat Score"] = threat.optInt("threat_score", 0)
                data["Is VPN"] = json.optBoolean("is_vpn")
                data["Is Known Abuser"] = threat.optBoolean("is_known_abuser")
                data["Is Known Attacker"] = threat.optBoolean("is_known_attacker")
                data["Blocklists"] = threat.optJSONArray("blocklists")?.length() ?: 0
                data["Country"] = json.optString("country_code", "N/A")
                data["ISP"] = json.optJSONObject("asn")?.optString("name", "N/A") ?: "N/A"
            }
            "fraudlogix" -> {
                data["Risk Score"] = json.optString("RiskScore", "N/A")
                data["Proxy"] = json.optBoolean("Proxy")
                data["VPN"] = json.optBoolean("VPN")
                data["Tor"] = json.optBoolean("TOR")
                data["Data Center"] = json.optBoolean("DataCenter")
                data["Abnormal Traffic"] = json.optBoolean("AbnormalTraffic")
                data["Recently Seen"] = json.optInt("RecentlySeen", 0)
                data["Search Engine Bot"] = json.optBoolean("SearchEngineBot")
                data["Masked Devices"] = json.optBoolean("MaskedDevices")
                data["Country"] = json.optString("CountryCode", "N/A")
                data["ISP"] = json.optString("ISP", "N/A")
                data["Connection Type"] = json.optString("ConnectionType", "N/A")
            }
            "ipgeolocation" -> {
                val security = json.optJSONObject("security") ?: JSONObject()
                data["Threat Score"] = security.optInt("threat_score", 0)
                data["Is Known Attacker"] = security.optBoolean("is_known_attacker")
                data["Is Bot"] = security.optBoolean("is_bot")
                data["Is VPN"] = security.optBoolean("is_vpn")
                data["Is Tor"] = security.optBoolean("is_tor")
                data["Is Proxy"] = security.optBoolean("is_proxy")
            }
            "pulsedive" -> {
                data["Risk"] = json.optString("risk", "N/A").replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
                data["Threats"] = json.optJSONObject("summary")?.optJSONObject("links")?.optInt("threat", 0) ?: 0
                data["Port Count"] = json.optJSONObject("properties")?.optJSONArray("port")?.length() ?: 0
            }
            "ipapi.is" -> {
                data["Is Proxy"] = json.optBoolean("is_proxy")
                data["Is VPN"] = json.optBoolean("is_vpn")
                data["Is Abuser"] = json.optBoolean("is_abuser")
                data["Abuser Score"] = json.optInt("abuser_score", 0)
                data["Is Datacenter"] = json.optBoolean("is_datacenter")
                data["Type"] = json.optString("type", "N/A")
            }
        }
        return data
    }

    private fun updateUiWithAllResults(results: List<ApiResult>, timestamp: Long? = null) {
        binding.progressBar.visibility = View.GONE
        binding.errorText.visibility = View.GONE
        binding.refreshButton.isEnabled = true
        binding.resultsContainer.removeAllViews()

        if (timestamp != null) {
            val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
            val formattedDate = sdf.format(Date(timestamp))
            binding.offlineStatusText.text = getString(R.string.offline_status, formattedDate)
            binding.offlineStatusText.visibility = View.VISIBLE
        }

        val inflater = LayoutInflater.from(this)

        results.forEach { result ->
            val cardView = inflater.inflate(R.layout.api_result_card, binding.resultsContainer, false)
            val cardTitle = cardView.findViewById<TextView>(R.id.apiCardTitle)
            val cardResultsContainer = cardView.findViewById<LinearLayout>(R.id.apiCardResultsContainer)

            cardTitle.text = result.apiName

            result.data.forEach { (key, value) ->
                val rowView = inflater.inflate(R.layout.info_row, cardResultsContainer, false)
                val labelTextView = rowView.findViewById<TextView>(R.id.infoLabel)
                val valueTextView = rowView.findViewById<TextView>(R.id.infoValue)
                labelTextView.text = key

                val displayValue: String
                var isHighlight = false

                when (value) {
                    is Boolean -> {
                        displayValue = if (value) "Yes" else "No"
                        isHighlight = value
                    }
                    is Int -> {
                        displayValue = value.toString()
                        isHighlight = value > 75
                    }
                    is String -> {
                        displayValue = value
                        if ((key == "Risk Score" || key == "Risk") && listOf("high", "extreme", "critical", "medium").contains(value.lowercase())) {
                            isHighlight = true
                        }
                    }
                    else -> {
                        displayValue = value.toString()
                    }
                }

                valueTextView.text = displayValue
                valueTextView.setTextColor(
                    ContextCompat.getColor(this, if (isHighlight) R.color.red_highlight else R.color.white_text)
                )

                cardResultsContainer.addView(rowView)
            }

            binding.resultsContainer.addView(cardView)
        }
    }

    private fun showError(message: String) {
        binding.progressBar.visibility = View.GONE
        binding.resultsContainer.removeAllViews()
        binding.errorText.text = message
        binding.errorText.visibility = View.VISIBLE
        binding.refreshButton.isEnabled = true
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun saveApiKey(apiKeyName: String, apiKeyValue: String) {
        sharedPreferences.edit {
            putString(apiKeyName, apiKeyValue)
        }
    }

    private fun getApiKey(apiKeyName: String): String? {
        return sharedPreferences.getString(apiKeyName, null)
    }

    private fun saveToHistory(ip: String) {
        val history = getHistory().toMutableList()
        if (history.contains(ip)) {
            history.remove(ip)
        }
        history.add(0, ip)
        val historyToSave = history.take(50)
        val json = Gson().toJson(historyToSave)
        sharedPreferences.edit {
            putString("ip_history", json)
        }
    }

    private fun getHistory(): List<String> {
        val json = sharedPreferences.getString("ip_history", null)
        return if (json != null) {
            val type = object : TypeToken<List<String>>() {}.type
            Gson().fromJson(json, type)
        } else {
            emptyList()
        }
    }

    private fun saveResultsToCache(ip: String, results: List<ApiResult>) {
        val cache = getCache()
        cache[ip] = CachedResult(System.currentTimeMillis(), results)

        if (cache.size > 50) {
            val oldestEntry = cache.minByOrNull { it.value.timestamp }
            oldestEntry?.let { cache.remove(it.key) }
        }

        val json = Gson().toJson(cache)
        sharedPreferences.edit {
            putString("ip_cache", json)
        }
    }

    private fun getResultFromCache(ip: String): CachedResult? {
        return getCache()[ip]
    }

    private fun getCache(): MutableMap<String, CachedResult> {
        val json = sharedPreferences.getString("ip_cache", null)
        return if (json != null) {
            val type = object : TypeToken<MutableMap<String, CachedResult>>() {}.type
            Gson().fromJson(json, type)
        } else {
            mutableMapOf()
        }
    }

    private fun isNetworkAvailable(): Boolean {
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork ?: return false
        val activeNetwork = connectivityManager.getNetworkCapabilities(network) ?: return false
        return when {
            activeNetwork.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> true
            activeNetwork.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> true
            activeNetwork.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> true
            else -> false
        }
    }
}