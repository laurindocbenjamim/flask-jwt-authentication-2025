class Sentiment {
  constructor(id, comment) {
    this.id = id;
    this.comment = comment;
  }
}

function sanitizeInput(input) {
  // Remove any script tags
  let sanitizedInput = input.replace(/<script[^>]*?>.*?<\/script>/gi, "");
  // Encode special characters
  sanitizedInput = sanitizedInput.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return sanitizedInput;
}

function sanitizeInput_2(str) {
  var div = document.createElement("div");
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

function filterString(input) {
  // This regular expression matches words with or without accentuation and punctuation
  var regex = /[A-Za-zÀ-ÖØ-öø-ÿ.,;?!'"\s]+/g;
  var result = input.match(regex);
  return result ? result.join('') : '';
}

function cleanForm() {
  try{
    var inputs = document
    .getElementById("subscriberForm")
    .getElementsByTagName("input");
  // Clear all input type="text" fields
  for (var i = 0; i < inputs.length; i++) {
    if (
      inputs[i].type.toLowerCase() == "text" ||
      inputs[i].type.toLowerCase() == "email"
    ) {
      inputs[i].value = "";
    }
  }
  }catch(err){}
}

var navCharts = document.getElementById('nav-charts')

document
  .getElementById("sentimentAnalyserForm")
  .addEventListener("submit", async (e) => {
    e.preventDefault();

    const baseUrl = window.location.origin;
    const dataForm = new FormData();
    // Set the initial progress
    var progress = 0;

    //const data = [{'name': 'laurindo', 'age': 12},{'name': 'mauro', 'age': 111}]

    var csrfToken = document
      .querySelector('meta[name="csrf-token"]')
      .getAttribute("content");
    var progressBar = document.querySelector(".progress-bar");
    var progressProcess = document.getElementById("progress-process");
    progressProcess.style.display = "none";
    // Update the progress bar's width and aria-valuenow attribute
    progressBar.style.width = progress + "%";
    progressBar.setAttribute("aria-valuenow", Math.round(progress));

    var alertmessage = document.querySelector(".form-message p");
    var response = document.getElementById("response");
    var comment = filterString(document.getElementById("comment").value) //sanitizeInput(document.getElementById("comment").value);
    var visualize = document.getElementById('visualize')

    //navCharts.style.display = 'none'

    let decimalPlace = 2; // number of decimal places
    let factor = Math.pow(10, decimalPlace);

    if (comment.length > 500) {
      return;
    }

    const headers = new Headers();
    headers.append("X-CSRF-Token", csrfToken);
    headers.append("Authorization", ` Bearer ${csrfToken}`);
    var obj = new Sentiment(1, comment);
    dataForm.append("comment", obj.comment);
    //
    progressProcess.style.display = "block";
    try { 
      const res = await fetch(
        `${baseUrl}/data-science/project/emotion-detector/${csrfToken}`,
        {
          method: "POST",
          body: dataForm,
          headers: headers
        }
      );

      const resData = await res.json();

      //console.log(resData);

      if (resData) {
        if (resData[1] == 400) {
          alertmessage.classList.add(resData[0].category);
          alertmessage.textContent = "";
          alertmessage.textContent = resData[0].message;
        } else if ((resData[1] == 401) | (resData[1] == 403)) {
          window.open(baseUrl + "/" + resData[0].redirectUrl, "_self");
        } else if (resData[1] == 200) {
          // Calculate the increment for each user
          var increment = 100 / resData[0].emotions.length;

          
          //
          cleanForm();
          let max_score = 0;
          const emotions = resData[0].emotions;
          emotions.forEach((element, index) => {
            setTimeout(() => {
              visualize.style.display = 'block'
              progress += increment;
              progressBar.textContent = `${progress}%`;
              //progressEmmotions(progress);

              var ol = document.createElement("ol");
              ol.className = "list-group list-group-numbered";
              var p = document.createElement("p");
              var li_anger = document.createElement("li");
              var li_disgust = document.createElement("li");
              var li_fear = document.createElement("li");
              var li_joy = document.createElement("li");
              var li_sadness = document.createElement("li");

              li_anger.className =
                "list-group-item d-flex justify-content-between align-items-start";

              var divChild = document.createElement("div");
              divChild.className = "fw-bold";
              divChild.textContent = "Anger";

              var divParent = document.createElement("div");
              divParent.className = "ms-2 me-auto";
              p.textContent = `The anger is a bad feeling. Score: [${element.anger}]`;

              var span = document.createElement("span");
              span.className = "badge text-bg-primary rounded-pill";

              span.textContent = `${Math.round(
                parseFloat(element.anger) * factor
              )}%`;
              max_score =
                parseFloat(element.anger) > max_score
                  ? parseFloat(element.anger)
                  : max_score;

              if (max_score == parseFloat(element.anger)) {
                li_anger.classList.add("active");
                li_disgust.classList.remove("active");
                li_fear.classList.remove("active");
                li_joy.classList.remove("active");
                li_sadness.classList.remove("active");
              }
              divParent.appendChild(divChild);
              divParent.appendChild(p);
              li_anger.appendChild(divParent);
              li_anger.appendChild(span);

              /**
               *
               */

              var p_disgust = document.createElement("p");

              li_disgust.className =
                "list-group-item d-flex justify-content-between align-items-start";

              var divChild_disgust = document.createElement("div");
              divChild_disgust.className = "fw-bold";
              divChild_disgust.textContent = "DISGUST";

              var divParent_disgust = document.createElement("div");
              divParent_disgust.className = "ms-2 me-auto";

              var span_disgust = document.createElement("span");
              span_disgust.className = "badge text-bg-primary rounded-pill";
              span_disgust.textContent = `${Math.round(
                parseFloat(element.disgust) * factor
              )}%`;

              p_disgust.textContent = `The Disgust is a bad feeling. Score: [${element.disgust}]`;

              max_score =
                parseFloat(element.disgust) > max_score
                  ? parseFloat(element.disgust)
                  : max_score;

              if (max_score == parseFloat(element.disgust)) {
                li_anger.classList.remove("active");
                li_disgust.classList.add("active");
                li_fear.classList.remove("active");
                li_joy.classList.remove("active");
                li_sadness.classList.remove("active");
              }

              divParent_disgust.appendChild(divChild_disgust);
              divParent_disgust.appendChild(p_disgust);

              li_disgust.appendChild(divParent_disgust);
              li_disgust.appendChild(span_disgust);

              /**
               *
               */

              var p_fear = document.createElement("p");

              li_fear.className =
                "list-group-item d-flex justify-content-between align-items-start";

              var divChild_fear = document.createElement("div");
              divChild_fear.className = "fw-bold";
              divChild_fear.textContent = "FEAR";

              var divParent_fear = document.createElement("div");
              divParent_fear.className = "ms-2 me-auto";

              var span_fear = document.createElement("span");
              span_fear.className = "badge text-bg-primary rounded-pill";
              span_fear.textContent = `${Math.round(
                parseFloat(element.fear) * factor
              )}%`;

              p_fear.textContent = `The Fear is a bad feeling. Score: [${element.fear}]`;
              max_score =
                parseFloat(element.anger) > max_score
                  ? parseFloat(element.fear)
                  : max_score;

              if (max_score == parseFloat(element.fear)) {
                li_anger.classList.remove("active");
                li_disgust.classList.remove("active");
                li_fear.classList.add("active");
                li_joy.classList.remove("active");
                li_sadness.classList.remove("active");
              }

              divParent_fear.appendChild(divChild_fear);
              divParent_fear.appendChild(p_fear);

              li_fear.appendChild(divParent_fear);
              li_fear.appendChild(span_fear);

              /**
               *
               */

              var p_joy = document.createElement("p");

              li_joy.className =
                "list-group-item d-flex justify-content-between align-items-start";
              li_joy.id = "joy-element";

              var divChild_joy = document.createElement("div");
              divChild_joy.className = "fw-bold";
              divChild_joy.textContent = "JOY";

              var divParent_joy = document.createElement("div");
              divParent_joy.className = "ms-2 me-auto";

              var span_joy = document.createElement("span");
              span_joy.className = "badge text-bg-primary rounded-pill";
              span_joy.textContent = `${Math.round(
                parseFloat(element.joy) * factor
              )}%`;

              p_joy.textContent = `The Joy is a GOOD feeling. Score: [${element.joy}]`;

              max_score =
                parseFloat(element.joy) > max_score
                  ? parseFloat(element.joy)
                  : max_score;

              if (max_score == parseFloat(element.joy)) {
                li_anger.classList.remove("active");
                li_disgust.classList.remove("active");
                li_fear.classList.remove("active");
                li_joy.classList.add("active");
                li_sadness.classList.remove("active");
                li_joy.classList.add("active");
                li_joy.setAttribute("data-bs-toggle", "tooltip");
                li_joy.setAttribute("data-bs-placement", "top");
                li_joy.setAttribute("data-bs-custom-class", "custom-tooltip");
                li_joy.setAttribute(
                  "data-bs-title",
                  `This is the dominante emotion detected with ${max_score}% of max score`
                );
              }

              divParent_joy.appendChild(divChild_joy);
              divParent_joy.appendChild(p_joy);

              li_joy.appendChild(divParent_joy);
              li_joy.appendChild(span_joy);

              /**
               *
               */

              var p_sadness = document.createElement("p");

              li_sadness.className =
                "list-group-item d-flex justify-content-between align-items-start";

              var divChild_sadness = document.createElement("div");
              divChild_sadness.className = "fw-bold";
              divChild_sadness.textContent = "SADNESS";

              var divParent_sadness = document.createElement("div");
              divParent_sadness.className = "ms-2 me-auto";

              var span_sadness = document.createElement("span");
              span_sadness.className = "badge text-bg-primary rounded-pill";
              span_sadness.textContent = `${Math.round(
                parseFloat(element.sadness) * factor
              )}%`;

              p_sadness.textContent = `The Sadness is a BAD feeling. Score: [${element.sadness}]`;

              max_score =
                parseFloat(element.sadness) > max_score
                  ? parseFloat(element.sadness)
                  : max_score;

              if (max_score == parseFloat(element.sadness)) {
                li_anger.classList.remove("active");
                li_disgust.classList.remove("active");
                li_fear.classList.remove("active");
                li_joy.classList.remove("active");
                li_sadness.classList.add("active");
              }

              divParent_sadness.appendChild(divChild_sadness);
              divParent_sadness.appendChild(p_sadness);

              li_sadness.appendChild(divParent_sadness);
              li_sadness.appendChild(span_sadness);

              /* ==============   =============*/

              ol.appendChild(li_anger);
              ol.appendChild(li_disgust);
              ol.appendChild(li_fear);
              ol.appendChild(li_joy);
              ol.appendChild(li_sadness);

              response.innerHTML = "";
              response.appendChild(ol);

              // Update the progress bar's width and aria-valuenow attribute
              progressBar.style.width = progress + "%";
              progressBar.setAttribute("aria-valuenow", Math.round(progress));

              // Log the progress
              console.log("Progress: " + Math.round(progress) + "%");
              // Log the progress
              console.log("Progress: " + Math.round(progress) + "%");

              const data = [
                {"emotions":['Anger', 'Disgust', 'Fear', 'Joy', 'Sadness'], 
                  "scores": [
                    Math.round(parseFloat(element.anger) * factor), 
                    Math.round(parseFloat(element.disgust) * factor),
                    Math.round(parseFloat(element.fear) * factor), 
                    Math.round(parseFloat(element.joy) * factor), 
                    Math.round(parseFloat(element.sadness) * factor)
                  ]
                }]
              localStorage.setItem("emotions", JSON.stringify(data))

              //displayChart('pie', data)
            }, index * 1000); // Adjust the delay as needed
          });

          alertmessage.classList.add(resData[0].category);
          alertmessage.textContent = "";
          alertmessage.textContent = resData[0].message;
        }
      }
    } catch (err) {
      console.log(err);
      console.log(err.message);
    }
  });


  document.getElementById('visualize').addEventListener('click', e => {
    
    navCharts.style.display = 'flex'
  })

  document.getElementById('line-chart').addEventListener('click', e =>{
    const emotions = JSON.parse(localStorage.getItem('emotions'))
    
    if(emotions){
      if(emotions.length > 0){       
        displayChart('line', emotions)
      }
    }
  })

  document.getElementById('bar-line-chart').addEventListener('click', e =>{
    const emotions = JSON.parse(localStorage.getItem('emotions'))
    
    if(emotions){
      if(emotions.length > 0){       
        displayChart('bar', emotions)
      }
    }
  })

  document.getElementById('pie-chart').addEventListener('click', e =>{
    const emotions = JSON.parse(localStorage.getItem('emotions'))
    
    if(emotions){
      if(emotions.length > 0){       
        displayChart('pie', emotions)
      }
    }
    

  })

/**
 *
 */

function displayChart(chart, data) {
  var container = document.getElementById("chart-container");
  var canvas = document.createElement("canvas");
  
  if (chart) {
    if (chart == "bar") {
      removeCanvasChildElement(container);

      canvas.setAttribute("id", "barChart");
      canvas.className = "bar-chart";
      canvas.style = "width:100%;max-width:700px";
      container.appendChild(canvas);
      barChart(chart, "barChart",data);
    } else if (chart == "line") {
      removeCanvasChildElement(container);

      canvas.setAttribute("id", "lineChart");
      canvas.style = "width:100%;max-width:700px";
      container.appendChild(canvas);
      lineChart(data);
    } else if (chart == "multipleline") {
      removeCanvasChildElement(container);

      canvas.setAttribute("id", "multipleLineChart");
      canvas.style = "width:100%;max-width:700px";
      container.appendChild(canvas);
      multipleLineChart(data);
    } else if (chart == "pie") {
      removeCanvasChildElement(container);

      canvas.setAttribute("id", "pieChart");
      canvas.style = "width:100%;max-width:700px";
      container.appendChild(canvas);
      pieChart(data);
    } else if (chart == "doughnut") {
      removeCanvasChildElement(container);

      canvas.setAttribute("id", "doughnutChart");
      canvas.style = "width:100%;max-width:700px";
      container.appendChild(canvas);
      doughnutChart(data);
    }
  }
}

/**
 *  This method is used to remove existent canvas child element from
 * the chart container
 */
function removeCanvasChildElement(container) {
  try {
    var old = document.querySelector("canvas");
    if (old) {
      container.removeChild(old);
    } else {
      console.log(old);
    }
  } catch (error) {
    console.log(error);
  }
}

/**
 *
 */
let barChart = (type, tagID,data) => {
  //console.log(data[0].scores[0])
  const xValues = data[0].emotions;
  const yValues = data[0].scores;
  const barColors = ["#b91d47", "#00aba9", "#2b5797", "#e8c3b9", "#1e7145"];

  new Chart(`${tagID}`, {
    type: `${type}`,
    data: {
      labels: xValues,
      datasets: [
        {
          backgroundColor: barColors,
          data: yValues ,
        },
      ],
    },
    options: {
      title: {
        display: true,
        text: "Emotions Rate Analysis",
      },
    },
  });
};

var lineChart = (data) => {
  const xValues = data[0].emotions;
  const yValues = data[0].scores;
  const barColors = ["#b91d47", "#00aba9", "#2b5797", "#e8c3b9", "#1e7145"];

  new Chart("lineChart", {
    type: "line",
    data: {
      labels: xValues,
      datasets: [
        {
          fill: false,
          lineTension: 0,
          backgroundColor: "rgba(0,0,255,1.0)",
          borderColor: "rgba(0,0,255,0.1)",
          data: yValues,
        },
      ],
    },
    options: {
      title: {
        display: true,
        text: "Emotions Rate Analysis",
      },
      legend: { display: false },
      scales: {
        yAxes: [{ ticks: { min: 6, max: 100 } }],
      },
    },
  });
};

let multipleLineChart = (data) => {
  const xValues = data[0].emotions;
  const yValues = data[0].scores;

  new Chart("multipleLineChart", {
    type: "line",
    data: {
      labels: xValues,
      datasets: [
        {
          fill: false,
          lineTension: 0,
          backgroundColor: "rgba(0,0,255,1.0)",
          borderColor: "rgba(0,0,255,0.1)",
          data: yValues,
        },
      ],
    },
    options: {
      title: {
        display: true,
        text: "Emotions Rate Analysis",
      },
      legend: { display: false },
    },
  });
};

let pieChart = (data) => {
  const xValues = data[0].emotions;
  const yValues = data[0].scores;
  const barColors = ["#b91d47", "#00aba9", "#2b5797", "#e8c3b9", "#1e7145"];

  new Chart("pieChart", {
    type: "pie",
    data: {
      labels: xValues,
      datasets: [
        {
          backgroundColor: barColors,
          data: yValues,
        },
      ],
    },
    options: {
      title: {
        display: true,
        text: "Emotions Rate Analysis",
      },
    },
  });
};

let doughnutChart = (data) => {
  const xValues = data[0].emotions;
  const yValues = data[0].scores;
  const barColors = ["#b91d47", "#00aba9", "#2b5797", "#e8c3b9", "#1e7145"];

  new Chart("doughnutChart", {
    type: "doughnut",
    data: {
      labels: xValues,
      datasets: [
        {
          backgroundColor: barColors,
          data: yValues,
        },
      ],
    },
    options: {
      title: {
        display: true,
        text: "Emotions Rate Analysis",
      },
    },
  });
};
