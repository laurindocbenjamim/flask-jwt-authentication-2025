


from .cv_customiser_prompts import CvPrompts
from app.utils import OpenAiApi

# Customize CV
def cv_customizer_with_chat_gpt(*, client_cv, job_requirement):
    if not client_cv:
        return False, "The client cv content is required."
    elif not job_requirement:
        return False, "The Job requirements is required"

    prompt=CvPrompts()
    try:
        cv_optimization_prompt=prompt.get(job_description=job_requirement, cv_content=client_cv, id=1)
        #cv_optimization_prompt= prompt.get_refined_prompt(job_description=job_requirement, cv_content=client_cv)
        optimise=cv_optimization_prompt.format(
                            job_description=job_requirement,
                            cv_content=client_cv
                        )
        openai_api = OpenAiApi()
        
        return openai_api.request_with_model_4(prompt=optimise)
    except Exception as e:
        return False, str(e)